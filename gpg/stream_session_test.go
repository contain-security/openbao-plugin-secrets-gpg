package gpg

import (
	"sync"
	"testing"
	"time"
)

func TestSessionStore_CreateAndGet(t *testing.T) {
	store := newSessionStore()

	sess := &streamSession{
		id:          "test-id",
		sessionType: sessionTypeSign,
		keyName:     "key1",
		lastAccess:  time.Now(),
	}
	if err := store.create(sess); err != nil {
		t.Fatalf("unexpected create error: %v", err)
	}

	got, ok := store.get("test-id")
	if !ok {
		t.Fatal("expected to find session")
	}
	if got.keyName != "key1" {
		t.Fatalf("expected keyName=key1, got %s", got.keyName)
	}

	_, ok = store.get("nonexistent")
	if ok {
		t.Fatal("expected nonexistent session to not be found")
	}
}

func TestSessionStore_Remove(t *testing.T) {
	store := newSessionStore()

	sess := &streamSession{id: "rm-id", lastAccess: time.Now()}
	store.create(sess)

	if store.sessionCount.Load() != 1 {
		t.Fatalf("expected count=1, got %d", store.sessionCount.Load())
	}

	store.remove("rm-id")
	if store.sessionCount.Load() != 0 {
		t.Fatalf("expected count=0 after remove, got %d", store.sessionCount.Load())
	}

	// Double remove should not decrement below zero.
	store.remove("rm-id")
	if store.sessionCount.Load() != 0 {
		t.Fatalf("expected count=0 after double remove, got %d", store.sessionCount.Load())
	}
}

func TestSessionStore_MaxSessionsLimit(t *testing.T) {
	store := newSessionStore()
	store.maxSessions = 3

	for i := 0; i < 3; i++ {
		id, _ := generateSessionID()
		err := store.create(&streamSession{id: id, lastAccess: time.Now()})
		if err != nil {
			t.Fatalf("create %d should succeed: %v", i, err)
		}
	}

	// Fourth should fail
	id, _ := generateSessionID()
	err := store.create(&streamSession{id: id, lastAccess: time.Now()})
	if err == nil {
		t.Fatal("expected error when exceeding max sessions")
	}

	// Count should still be 3 (not 4)
	if store.sessionCount.Load() != 3 {
		t.Fatalf("expected count=3, got %d", store.sessionCount.Load())
	}
}

func TestSessionStore_ConcurrentCreateMaxSessions(t *testing.T) {
	store := newSessionStore()
	store.maxSessions = 10

	var wg sync.WaitGroup
	successes := make(chan struct{}, 100)
	failures := make(chan struct{}, 100)

	// Launch 50 goroutines all trying to create sessions concurrently
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, _ := generateSessionID()
			err := store.create(&streamSession{id: id, lastAccess: time.Now()})
			if err != nil {
				failures <- struct{}{}
			} else {
				successes <- struct{}{}
			}
		}()
	}
	wg.Wait()
	close(successes)
	close(failures)

	successCount := 0
	for range successes {
		successCount++
	}
	failCount := 0
	for range failures {
		failCount++
	}

	if successCount != 10 {
		t.Fatalf("expected exactly 10 successes, got %d", successCount)
	}
	if failCount != 40 {
		t.Fatalf("expected exactly 40 failures, got %d", failCount)
	}
	if store.sessionCount.Load() != 10 {
		t.Fatalf("expected count=10, got %d", store.sessionCount.Load())
	}
}

func TestSessionStore_Cleanup(t *testing.T) {
	store := newSessionStore()
	store.timeout = 50 * time.Millisecond

	// Create sessions: one fresh, one expired
	fresh := &streamSession{id: "fresh", lastAccess: time.Now()}
	expired := &streamSession{id: "expired", lastAccess: time.Now().Add(-100 * time.Millisecond)}

	store.create(fresh)
	store.create(expired)

	if store.sessionCount.Load() != 2 {
		t.Fatalf("expected count=2, got %d", store.sessionCount.Load())
	}

	removed := store.cleanup()
	if removed != 1 {
		t.Fatalf("expected 1 removed, got %d", removed)
	}

	_, ok := store.get("fresh")
	if !ok {
		t.Fatal("fresh session should still exist")
	}
	_, ok = store.get("expired")
	if ok {
		t.Fatal("expired session should be gone")
	}

	if store.sessionCount.Load() != 1 {
		t.Fatalf("expected count=1 after cleanup, got %d", store.sessionCount.Load())
	}
}

func TestSessionStore_ConcurrentRemoveAndCleanup(t *testing.T) {
	store := newSessionStore()
	store.timeout = 1 * time.Millisecond

	// Create 20 sessions all already expired
	for i := 0; i < 20; i++ {
		id, _ := generateSessionID()
		store.create(&streamSession{
			id:         id,
			lastAccess: time.Now().Add(-10 * time.Millisecond),
		})
	}

	// Run cleanup and remove concurrently
	var wg sync.WaitGroup

	// Cleanup from one goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.cleanup()
	}()

	// Remove all from another goroutine
	wg.Add(1)
	go func() {
		defer wg.Done()
		store.sessions.Range(func(key, _ any) bool {
			store.remove(key.(string))
			return true
		})
	}()

	wg.Wait()

	// Count must be zero (not negative)
	count := store.sessionCount.Load()
	if count != 0 {
		t.Fatalf("expected count=0, got %d (negative means double-decrement bug)", count)
	}
}

func TestSessionStore_KillAll(t *testing.T) {
	store := newSessionStore()

	for i := 0; i < 5; i++ {
		id, _ := generateSessionID()
		store.create(&streamSession{id: id, lastAccess: time.Now()})
	}

	store.killAll()

	if store.sessionCount.Load() != 0 {
		t.Fatalf("expected count=0 after killAll, got %d", store.sessionCount.Load())
	}

	// Verify no sessions remain
	count := 0
	store.sessions.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Fatalf("expected 0 sessions in map, got %d", count)
	}
}

func TestGenerateSessionID(t *testing.T) {
	id1, err := generateSessionID()
	if err != nil {
		t.Fatal(err)
	}
	id2, err := generateSessionID()
	if err != nil {
		t.Fatal(err)
	}

	if len(id1) != 32 { // 16 bytes = 32 hex chars
		t.Fatalf("expected 32-char hex id, got %d chars", len(id1))
	}
	if id1 == id2 {
		t.Fatal("two generated IDs should not be equal")
	}
}

func TestHashClientToken(t *testing.T) {
	h1 := hashClientToken("token-a")
	h2 := hashClientToken("token-a")
	h3 := hashClientToken("token-b")

	if h1 != h2 {
		t.Fatal("same token should produce same hash")
	}
	if h1 == h3 {
		t.Fatal("different tokens should produce different hashes")
	}
	if len(h1) != 64 { // SHA-256 = 32 bytes = 64 hex chars
		t.Fatalf("expected 64-char hex hash, got %d", len(h1))
	}
}

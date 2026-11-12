package brain

import (
	"path/filepath"
	"testing"
)

func TestLearningReordersByEvidence(t *testing.T) {
	k := New()
	// "sqli" keeps paying off; "xss" never does.
	for i := 0; i < 10; i++ {
		k.Observe("sqli", "query", "none", true)
		k.Observe("xss", "query", "none", false)
	}
	ranked := k.Rank("payload", []string{"xss", "sqli"})
	if ranked[0] != "sqli" {
		t.Fatalf("expected the proven family first, got %v", ranked)
	}
}

func TestOptimisticPriorBeatsProvenDud(t *testing.T) {
	k := New()
	for i := 0; i < 10; i++ {
		k.Observe("xss", "f", "none", false) // proven dud
	}
	// "newfam" has never been tried; it should outrank the proven dud so the
	// engine keeps exploring the unknown.
	ranked := k.Rank("payload", []string{"xss", "newfam"})
	if ranked[0] != "newfam" {
		t.Fatalf("optimistic prior should rank the untried option first, got %v", ranked)
	}
}

func TestTopFields(t *testing.T) {
	k := New()
	for i := 0; i < 5; i++ {
		k.Observe("sqli", "query", "none", true)
		k.Observe("sqli", "noise", "none", false)
	}
	top := k.TopFields(1)
	if len(top) != 1 || top[0] != "query" {
		t.Fatalf("expected the reactive field on top, got %v", top)
	}
}

func TestSaveLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mem.json")
	k := New()
	k.Observe("sqli", "query", "none", true)
	k.NoteFramework("socket.io")
	if err := k.Save(path); err != nil {
		t.Fatal(err)
	}
	k2, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if k2.Payloads["sqli"] == nil || k2.Payloads["sqli"].Hits != 1 {
		t.Fatalf("learned weights did not survive a round trip: %+v", k2.Payloads)
	}
	if k2.Frameworks["socket.io"] != 1 {
		t.Error("framework tally did not persist")
	}
}

func TestLoadMissingFileIsEmpty(t *testing.T) {
	k, err := Load(filepath.Join(t.TempDir(), "nope.json"))
	if err != nil {
		t.Fatalf("missing memory file should be a fresh base, not an error: %v", err)
	}
	if k == nil || len(k.Payloads) != 0 {
		t.Fatal("expected an empty knowledge base")
	}
}

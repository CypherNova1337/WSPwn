package jsonx

import (
	"strings"
	"testing"
)

func TestParseAndLeaves(t *testing.T) {
	tree, ok := Parse(`{"id":7,"payload":{"name":"a","tags":[1,2]}}`)
	if !ok {
		t.Fatal("expected JSON")
	}
	leaves := Leaves(tree)
	want := map[string]bool{"id": true, "payload.name": true, "payload.tags.0": true, "payload.tags.1": true}
	if len(leaves) != len(want) {
		t.Fatalf("got %d leaves, want %d: %+v", len(leaves), len(want), leaves)
	}
	for _, l := range leaves {
		if !want[l.Path] {
			t.Errorf("unexpected leaf path %q", l.Path)
		}
	}
}

func TestParseRejectsScalar(t *testing.T) {
	if _, ok := Parse(`"just a string"`); ok {
		t.Error("a bare string should not parse as an injectable tree")
	}
	if _, ok := Parse(`not json at all`); ok {
		t.Error("non-JSON should not parse")
	}
}

func TestSetStringLeavesTreeIntact(t *testing.T) {
	tree, _ := Parse(`{"a":"x","b":"y"}`)
	out, err := SetString(tree, "a", "INJECT")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `"a":"INJECT"`) || !strings.Contains(out, `"b":"y"`) {
		t.Fatalf("bad set result: %s", out)
	}
	// Second call must see the original value, proving the tree was restored.
	out2, _ := SetString(tree, "a", "OTHER")
	if !strings.Contains(out2, `"a":"OTHER"`) || strings.Contains(out2, "INJECT") {
		t.Fatalf("tree not restored between sets: %s", out2)
	}
}

func TestMutateIdMath(t *testing.T) {
	tree, _ := Parse(`{"id":41}`)
	leaf := Leaves(tree)[0]
	out, ok := Mutate(tree, "id", "__WSPWN_IDINC__", leaf.Value)
	if !ok || !strings.Contains(out, `"id":42`) {
		t.Fatalf("id increment failed: ok=%v out=%s", ok, out)
	}
	if _, ok := Mutate(tree, "id", "__WSPWN_IDINC__", "not-a-number"); ok {
		t.Error("id math should not apply to non-numeric values")
	}
}

func TestMutateType(t *testing.T) {
	tree, _ := Parse(`{"v":"scalar"}`)
	out, ok := Mutate(tree, "v", "__WSPWN_ARRAY__", "scalar")
	if !ok || !strings.Contains(out, `"v":["scalar"]`) {
		t.Fatalf("array mutation failed: ok=%v out=%s", ok, out)
	}
}

func TestFieldName(t *testing.T) {
	if FieldName("a.b.id") != "id" {
		t.Error("FieldName should return last segment")
	}
	if FieldName("id") != "id" {
		t.Error("FieldName of a top-level key should be itself")
	}
}

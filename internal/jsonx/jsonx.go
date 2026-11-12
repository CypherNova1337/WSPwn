// Package jsonx gives the fuzzer structural awareness of JSON messages. Most
// WebSocket traffic is JSON, and a smart fuzzer injects into one field at a
// time — leaving the rest of the message valid so the server reaches the code
// that parses the field under test — rather than corrupting the whole frame.
// It also applies the structural sentinels (turn a scalar into an array, bump a
// numeric id) that plain string substitution can't express.
package jsonx

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// Leaf is one scalar position in a JSON document, addressed by a dotted path.
type Leaf struct {
	Path  string      // e.g. "payload.id" or "args.0"
	Value interface{} // original scalar
}

// Parse reports whether raw is a JSON object/array and returns the decoded tree.
func Parse(raw string) (interface{}, bool) {
	var v interface{}
	dec := json.NewDecoder(strings.NewReader(strings.TrimSpace(raw)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return nil, false
	}
	switch v.(type) {
	case map[string]interface{}, []interface{}:
		return v, true
	default:
		return nil, false
	}
}

// Leaves lists every scalar position in the tree, deepest paths last.
func Leaves(tree interface{}) []Leaf {
	var out []Leaf
	walk("", tree, &out)
	sort.SliceStable(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

func walk(prefix string, v interface{}, out *[]Leaf) {
	switch t := v.(type) {
	case map[string]interface{}:
		for k, child := range t {
			walk(join(prefix, k), child, out)
		}
	case []interface{}:
		for i, child := range t {
			walk(join(prefix, strconv.Itoa(i)), child, out)
		}
	default:
		*out = append(*out, Leaf{Path: prefix, Value: v})
	}
}

func join(prefix, key string) string {
	if prefix == "" {
		return key
	}
	return prefix + "." + key
}

// FieldName returns the last segment of a path, which is what the brain keys
// its field scores on (so "id" is learned across messages, not "a.b.id").
func FieldName(path string) string {
	if i := strings.LastIndex(path, "."); i >= 0 {
		return path[i+1:]
	}
	return path
}

// SetString returns a copy of tree with the leaf at path replaced by s, encoded
// back to a JSON string.
func SetString(tree interface{}, path, s string) (string, error) {
	return setAndMarshal(tree, path, s)
}

// Mutate applies a structural sentinel to the leaf at path and returns the new
// JSON. It covers the type-confusion and authz-id cases that aren't plain
// string swaps.
func Mutate(tree interface{}, path, sentinel string, orig interface{}) (string, bool) {
	var nv interface{}
	switch sentinel {
	case "__WSPWN_ARRAY__":
		nv = []interface{}{orig}
	case "__WSPWN_OBJECT__":
		nv = map[string]interface{}{"wspwn": orig}
	case "__WSPWN_NULL__":
		nv = nil
	case "__WSPWN_BIGNUM__":
		nv = json.Number("999999999999999999999")
	case "__WSPWN_NEG__":
		nv = json.Number("-1")
	case "__WSPWN_IDINC__", "__WSPWN_IDDEC__", "__WSPWN_IDZERO__":
		n, ok := asInt(orig)
		if !ok {
			return "", false
		}
		switch sentinel {
		case "__WSPWN_IDINC__":
			nv = json.Number(strconv.FormatInt(n+1, 10))
		case "__WSPWN_IDDEC__":
			nv = json.Number(strconv.FormatInt(n-1, 10))
		default:
			nv = json.Number("0")
		}
	default:
		return "", false
	}
	s, err := setRaw(tree, path, nv)
	if err != nil {
		return "", false
	}
	return s, true
}

func asInt(v interface{}) (int64, bool) {
	switch t := v.(type) {
	case json.Number:
		n, err := t.Int64()
		return n, err == nil
	case float64:
		return int64(t), true
	case string:
		n, err := strconv.ParseInt(t, 10, 64)
		return n, err == nil
	}
	return 0, false
}

func setAndMarshal(tree interface{}, path, s string) (string, error) {
	return setRaw(tree, path, s)
}

// setRaw deep-walks a clone-free path set. Since Mutate/SetString are called
// once per payload against the original tree, we rebuild only the spine we
// touch by re-marshalling after an in-place set and restore.
func setRaw(tree interface{}, path string, nv interface{}) (string, error) {
	parts := strings.Split(path, ".")
	parent, key, restore, ok := locate(tree, parts)
	if !ok {
		return "", fmt.Errorf("path %q not found", path)
	}
	set(parent, key, nv)
	b, err := json.Marshal(tree)
	set(parent, key, restore) // leave the tree as we found it for the next payload
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// locate returns the parent container and key for a path, plus the current
// value so the caller can restore it.
func locate(tree interface{}, parts []string) (parent interface{}, key string, cur interface{}, ok bool) {
	node := tree
	for i := 0; i < len(parts)-1; i++ {
		switch t := node.(type) {
		case map[string]interface{}:
			node = t[parts[i]]
		case []interface{}:
			idx, err := strconv.Atoi(parts[i])
			if err != nil || idx < 0 || idx >= len(t) {
				return nil, "", nil, false
			}
			node = t[idx]
		default:
			return nil, "", nil, false
		}
	}
	last := parts[len(parts)-1]
	switch t := node.(type) {
	case map[string]interface{}:
		return node, last, t[last], true
	case []interface{}:
		idx, err := strconv.Atoi(last)
		if err != nil || idx < 0 || idx >= len(t) {
			return nil, "", nil, false
		}
		return node, last, t[idx], true
	}
	return nil, "", nil, false
}

func set(parent interface{}, key string, v interface{}) {
	switch t := parent.(type) {
	case map[string]interface{}:
		t[key] = v
	case []interface{}:
		if idx, err := strconv.Atoi(key); err == nil && idx >= 0 && idx < len(t) {
			t[idx] = v
		}
	}
}

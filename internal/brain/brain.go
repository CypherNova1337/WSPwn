// Package brain is WSPwn's memory. It is what makes the tool get better the
// longer it runs instead of firing the same list at every endpoint. Each time
// the fuzzer sends a payload, the result — did it make the server flinch? —
// feeds back here, raising the standing of the injection family, the JSON field
// name, and the encoding that worked, and quietly lowering the ones that never
// do. The next choice of what to try is drawn from those running scores, so a
// field that reacted on one endpoint is tried first on the next, and a payload
// class that has never once mattered sinks to the bottom.
//
// The scoring is a simple Bayesian success rate with an optimistic prior: an
// untried option is assumed promising (so the tool keeps exploring), and the
// estimate converges on the option's real hit rate as evidence accumulates.
// A --memory file lets that evidence survive across runs.
package brain

import (
	"encoding/json"
	"os"
	"sort"
	"sync"
)

// Stat is the running record for one option (a payload family, a field, …).
type Stat struct {
	Tries int `json:"tries"`
	Hits  int `json:"hits"`
}

// rate is the Bayesian-smoothed hit rate. The +1/+2 prior (Laplace) keeps a
// never-tried option (rate 0.5) ahead of one that has tried and always missed,
// which is what biases the engine toward exploring the unknown early and
// exploiting the proven later.
func (s Stat) rate() float64 {
	return float64(s.Hits+1) / float64(s.Tries+2)
}

// Knowledge is the whole accumulated picture of a target (or of everything the
// memory file has ever seen). It is safe for concurrent use.
type Knowledge struct {
	mu         sync.Mutex
	Payloads   map[string]*Stat `json:"payloads"`
	Fields     map[string]*Stat `json:"fields"`
	Encoders   map[string]*Stat `json:"encoders"`
	Frameworks map[string]int   `json:"frameworks"`
	ErrorToken string           `json:"error_token,omitempty"`
	AuthModel  string           `json:"auth_model,omitempty"`
}

// New returns an empty knowledge base.
func New() *Knowledge {
	return &Knowledge{
		Payloads:   map[string]*Stat{},
		Fields:     map[string]*Stat{},
		Encoders:   map[string]*Stat{},
		Frameworks: map[string]int{},
	}
}

// Load reads a memory file, returning a fresh base if it doesn't exist yet.
func Load(path string) (*Knowledge, error) {
	if path == "" {
		return New(), nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return New(), nil
		}
		return nil, err
	}
	k := New()
	if err := json.Unmarshal(b, k); err != nil {
		return nil, err
	}
	k.ensure()
	return k, nil
}

// Save writes the memory file (no-op for an empty path).
func (k *Knowledge) Save(path string) error {
	if path == "" {
		return nil
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	b, err := json.MarshalIndent(k, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

func (k *Knowledge) ensure() {
	if k.Payloads == nil {
		k.Payloads = map[string]*Stat{}
	}
	if k.Fields == nil {
		k.Fields = map[string]*Stat{}
	}
	if k.Encoders == nil {
		k.Encoders = map[string]*Stat{}
	}
	if k.Frameworks == nil {
		k.Frameworks = map[string]int{}
	}
}

// Observe records one trial: which payload family, field, and encoder were
// used, and whether the result was interesting (a hit). This is the single
// feedback point every attack result flows through.
func (k *Knowledge) Observe(payload, field, encoder string, hit bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ensure()
	bump(k.Payloads, payload, hit)
	if field != "" {
		bump(k.Fields, field, hit)
	}
	if encoder != "" {
		bump(k.Encoders, encoder, hit)
	}
}

func bump(m map[string]*Stat, key string, hit bool) {
	s := m[key]
	if s == nil {
		s = &Stat{}
		m[key] = s
	}
	s.Tries++
	if hit {
		s.Hits++
	}
}

// NoteFramework tallies a detected stack so a memory file builds a picture of
// what a target tends to run.
func (k *Knowledge) NoteFramework(name string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ensure()
	k.Frameworks[name]++
}

// Rank orders the given option keys best-first by learned score. Unknown keys
// get the optimistic prior, so a never-seen payload is tried ahead of a proven
// dud but behind a proven winner — exploration without forgetting what works.
func (k *Knowledge) Rank(kind string, keys []string) []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.ensure()
	m := k.pick(kind)
	out := append([]string(nil), keys...)
	sort.SliceStable(out, func(i, j int) bool {
		return score(m, out[i]) > score(m, out[j])
	})
	return out
}

// Score exposes the current learned rate for one option (for reporting).
func (k *Knowledge) Score(kind, key string) float64 {
	k.mu.Lock()
	defer k.mu.Unlock()
	return score(k.pick(kind), key)
}

func (k *Knowledge) pick(kind string) map[string]*Stat {
	switch kind {
	case "field":
		return k.Fields
	case "encoder":
		return k.Encoders
	default:
		return k.Payloads
	}
}

func score(m map[string]*Stat, key string) float64 {
	if s := m[key]; s != nil {
		return s.rate()
	}
	return 0.5 // optimistic prior for the unknown
}

// TopFields returns up to n field names learned to be the most reactive, which
// the fuzzer uses to decide where to spend extra budget first.
func (k *Knowledge) TopFields(n int) []string {
	k.mu.Lock()
	defer k.mu.Unlock()
	type kv struct {
		key string
		r   float64
		t   int
	}
	var all []kv
	for key, s := range k.Fields {
		if s.Tries > 0 {
			all = append(all, kv{key, s.rate(), s.Tries})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].r != all[j].r {
			return all[i].r > all[j].r
		}
		return all[i].t > all[j].t
	})
	var out []string
	for i := 0; i < len(all) && i < n; i++ {
		out = append(out, all[i].key)
	}
	return out
}

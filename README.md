# WSPwn

Maps a target's WebSocket attack surface, then reasons about it — discovers the
endpoints, works out how each one authenticates, and attacks the ones worth
attacking instead of spraying every payload at every socket.

![license](https://img.shields.io/badge/license-MIT-blue?style=flat-square)
![go](https://img.shields.io/badge/go-1.24%2B-00ADD8?style=flat-square)
![release](https://img.shields.io/badge/release-v1.0.0-brightgreen?style=flat-square)

## What it does

WebSockets get far less testing attention than the HTTP endpoints beside them,
and the usual tooling stops at "it connected". The interesting questions come
after the handshake: can a page on another origin open this socket as a
logged-in victim? Does the server trust whatever JSON the client sends? Is auth
a cookie the browser attaches for free?

WSPwn works the whole chain:

- **Discovery.** It reads the target page and the JavaScript it loads and pulls
  out every `ws://` / `wss://` URL and socket path the app actually refers to,
  then falls back to a curated list of conventional mount points. The endpoints
  a bundle names are the ones that are really wired up.
- **Fingerprinting.** From the path, the negotiated subprotocol and whatever the
  server pushes on connect, it names the stack — socket.io, SockJS, SignalR,
  ActionCable, graphql-ws, STOMP, Phoenix, MQTT, Centrifugo or raw — so it can
  speak each one correctly instead of guessing.
- **Recon checks.** It reasons about Cross-Site WebSocket Hijacking rather than
  guessing at it: an endpoint that accepts any `Origin` is only a problem if it
  also authenticates with cookies, so WSPwn establishes the auth model first and
  judges the Origin behaviour against it. It also flags plaintext `ws://` and
  unauthenticated access.
- **Adaptive fuzzing.** Before attacking an endpoint it learns what normal looks
  like — the shape of a routine reply and the shape of a "you sent garbage"
  reply — so an anomaly is a departure from what the server itself called
  normal, not a hardcoded error string. It injects into one JSON field at a
  time, judges every response against that baseline, and when a field reacts it
  spends extra budget right there.
- **Proof.** For a hijackable endpoint it writes a standalone CSWSH
  proof-of-concept page that connects from an attacker origin and prints the
  victim stream, so a report shows the real data at risk.

## It learns as it goes

WSPwn gets sharper the longer it runs. Every injection result — did the server
flinch? — feeds back into a running score for the payload family, the JSON field
name and the encoding that produced it. The next choice of what to try is drawn
from those scores, so a field that reacted on one endpoint is tried first on the
next, and a payload class that never matters sinks to the bottom. Point it at a
`--memory` file and that evidence survives across runs, so a repeat assessment
starts already knowing where this target tends to break.

## Why you'd use it

- **Finds the endpoints for you**, from the app's own code, not just a blind
  path list.
- **Reasons about CSWSH** — cookie auth plus an unvalidated Origin — instead of
  reporting every any-Origin server as vulnerable.
- **Speaks the framework.** It establishes a real session the right way for
  socket.io, graphql-ws, ActionCable, STOMP and others before it fuzzes.
- **Judges by learned baseline.** Reflections, time delays, fresh errors and
  size shifts are measured against the endpoint's own normal, keeping the noise
  down.
- **Gets smarter as it runs**, reordering its own effort toward what has been
  paying off, within a run and across runs.
- **Shows its work.** A live status line says what it's trying right now —
  endpoint, field, family, encoder, send rate — so a run is never a silent wait.
- **Proves the finding.** CSWSH comes with a working PoC, not just a label.

## Install

```bash
go install github.com/CypherNova1337/WSPwn/cmd/wspwn@latest
```

Or from a checkout:

```bash
git clone https://github.com/CypherNova1337/WSPwn
cd WSPwn
go build -o wspwn ./cmd/wspwn
```

Needs Go 1.24 or newer. The result is a single static binary with no runtime
dependencies.

## Usage

Point it at a target; it discovers, fingerprints and runs the recon checks:

```bash
wspwn -u https://site.example
```

**With an authenticated session** (so it can judge the auth model and CSWSH)

```bash
wspwn -u https://site.example --cookie 'session=abc123'
```

**Turn on adaptive fuzzing**

```bash
wspwn -u wss://site.example/ws --cookie 'session=abc123' --fuzz
```

**Mutate a message you captured**

```bash
wspwn -u wss://site.example/ws --fuzz --seed '{"action":"get","id":1}'
```

**Remember what it learns, run to run**

```bash
wspwn -u wss://site.example/ws --fuzz --memory target.mem
```

**Prove a CSWSH finding**

```bash
wspwn -u wss://site.example/ws --cookie 'session=abc123' --cswsh-poc ./pocs/
```

**A list of targets**

```bash
wspwn -l targets.txt --json report.json
```

**Through Burp**

```bash
wspwn -u wss://site.example/ws --fuzz --proxy http://127.0.0.1:8080
```

**Restrict the fuzzer to specific bug classes**

```bash
wspwn -u wss://site.example/ws --fuzz --families sqli,cmdi,authz
```

## Options

| Flag | Default | What it does |
|---|---|---|
| `-u` | — | Target URL (`http(s)://` or `ws(s)://`) |
| `-l` | — | File of targets, one per line |
| `--cookie` | — | Cookie header for an authenticated session |
| `-H` | — | Extra handshake header `Name: value` (repeatable) |
| `--subproto` | — | `Sec-WebSocket-Protocol` to offer (repeatable) |
| `--no-crawl` | off | Don't read the page/JS for endpoints |
| `--no-probe` | off | Don't probe common WebSocket paths |
| `--origin` | `https://wspwn-evil.example` | Foreign Origin used for the CSWSH test |
| `--fuzz` | off | Learn each endpoint's baseline and fuzz it |
| `--seed` | auto | Seed message to mutate (default: observed or framework greeting) |
| `--families` | all | Restrict fuzzing to these families (csv) |
| `--budget` | `400` | Max fuzz sends per endpoint |
| `--no-escalate` | off | Don't spend extra budget where a field reacts |
| `--memory` | — | Persist learned weights to this file and reuse them |
| `--cswsh-poc` | — | Write a CSWSH PoC HTML per hijackable endpoint into this dir |
| `--collector` | — | URL the CSWSH PoC exfiltrates received frames to |
| `--proxy` | — | Outbound proxy, e.g. Burp |
| `-k` | off | Skip TLS verification |
| `--timeout` | `12s` | Handshake timeout |
| `--idle` | `6s` | Per-message read wait |
| `--json` | — | Write the report as JSON to this file |
| `--no-progress` | — | Disable the live status line |
| `--no-color` | — | Disable colour |
| `-q` | — | Quiet: findings only |
| `--version` | — | Print version and exit |

Fuzzing families: `sqli`, `nosqli`, `xss`, `traversal`, `cmdi`, `ssti`,
`jsontype`, `authz`, `overflow`, `format`.

## Good to know

- **`--fuzz` writes to the target.** It sends crafted messages to live
  endpoints. Know that before running it on someone's production box.
- **CSWSH detection needs the victim cookie.** Without `--cookie` WSPwn can't
  establish that auth rides on the cookie, so it reports the weaker "Origin not
  validated" finding instead of confirming the hijack.
- **A reflected marker isn't automatically high severity.** It means the input
  came back; whether that's exploitable depends on where it lands. Check the
  evidence before writing it up.
- **The `--collector` in a PoC exfiltrates data.** Only point it at a host you
  control, and only for an authorised engagement.
- **Exit code is 1** when anything High or above is found, so a run slots into a
  CI gate.
- **It's not quiet.** Discovery probes paths and the fuzzer sends hundreds of
  messages per endpoint. Tune `--budget`, `--no-probe` and `--idle` for a
  lighter touch.

## Authorised use

Only against systems you own or have written permission to test. Opening a
WebSocket as another user, or reading a stream you weren't granted, is
unauthorised access regardless of how easy the bug was to find.

## License

MIT — see [LICENSE](LICENSE).

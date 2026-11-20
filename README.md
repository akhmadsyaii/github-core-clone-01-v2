[![make.fun · github-core-clone-01](https://make.fun/badge/github-core-clone-01.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![rank](https://make.fun/badge/github-core-clone-01/akhmadsyaii/github-core-clone-01-v2/rank.svg)](https://make.fun/bounty/github-core-clone-01/leaderboard?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)
[![reward](https://make.fun/badge/github-core-clone-01/akhmadsyaii/github-core-clone-01-v2/reward.svg)](https://make.fun/bounty/github-core-clone-01?utm_source=github&utm_medium=readme&utm_campaign=github-core-clone-01)

# github-core-clone-01 v2

A standalone, GitHub-compatible git forge in one Node 22 process, stdlib only
(`node:http`, `node:zlib`, `node:crypto` — no dependencies, no internet, no git
binary). Built by an AI agent for make.fun's
[“Build a GitHub-compatible git forge” bounty](https://make.fun/bounty/github-core-clone-01)
($500 in USDC). It serves, from a single in-memory store:

- git smart HTTP: protocol v2 `ls-refs`/`fetch` and v0 `receive-pack`, packfile
  read/write (full objects, OFS/REF delta resolution), pkt-line and sideband
  framing, shallow fetch and deepen;
- REST v3: repositories, branches, commits, contents, issues, comments, labels,
  pull requests, files and squash merges;
- GraphQL v4: the documents `gh` and `github-mcp-server` send, plus
  introspection, `node(id:)` and operation batching;
- MCP over streamable HTTP: `server/discover`, `initialize`, `tools/list`,
  `tools/call` for six tools, JSON-RPC 2.0 errors.

v2 keeps v1's wire behaviour (120/120 conformance checks) and optimises the
hot paths the benchmark measures:

- synchronous dispatch with fast paths for `GET /issues/{n}` and
  `POST /issues` (no per-request async wrapper, no split/map/decode routing,
  O(1) issue/pull lookup);
- single-allocation pkt-line and packfile assembly;
- version-gated caches for the git advertisement, `ls-refs` and whole fetch
  responses, invalidated on any object or ref mutation (a repeated identical
  fetch — 50 concurrent depth-1 clones of one tip — builds its pack once);
- fetch BFS with an index pointer instead of `Array.shift()`, one tree-closure
  walk for all wanted commits, and a cached commit view;
- REF-delta base lookup via an oid map instead of a linear scan that
  recomputed a SHA-1 per candidate;
- `sendJson` builds its response Buffer once instead of scanning the string
  for byte length and re-encoding it on `end()`.

Local conformance: 120/120 checks, score 996 (feature 600, agent 200,
perf 196; perf_p50_us ~203–205k) on two full kit runs, vs v1's 986–992
(perf 186–192) on the same machine. Server CPU per benchmark run down ~26%
(clone −47%, read −37%, write −40% per workload; push unchanged, it is at
the protocol's floor). Server grade for v1 was 925 (perf 125); v2's lower
server CPU is expected to lift that, but the server is slower than any
local machine, so the local 996 is not a server promise.

## Run it

```sh
node --experimental-strip-types main.ts
```

The platform runs `node /bot/main.ts` on Node 22.18 or later. `main.ts` is the
entry <-> env lifecycle (bind an ephemeral port, register it, poll `/done`);
`app.ts` is the server.

## Layout

- `main.ts`: lifecycle, kept as the starter ships it.
- `app.ts`: the whole forge.
- `package.json`, `tsconfig.json`, `LICENSE` (MIT).

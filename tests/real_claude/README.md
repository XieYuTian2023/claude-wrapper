# Official Claude Code audit fixture

`capture.py` launches an actual official executable with dummy credentials. A
local TLS API fixture returns deterministic model messages and retains the
requests for inspection. No live Anthropic login or model is exercised. Only
the optional US GeoIP preflight travels through the provided local proxy.

The optional `--tool-scenario` uses the real client's `Read`, `Write` and `Bash`
tools in a fresh workspace under `target/`. It reads a marker, writes a file,
runs a fixed local Python script to append to that same inode, and sends the
actual tool results back to the local model fixture. The script checks the
inherited Profile values, native `getenv`, absence of private bootstrap values,
and kernel denial of direct TCP/UDP connections. The socket probes send no
external application payload. The child probe checks that the native hostname and username
agree with the corresponding system commands. It records comparison results
without recording those names.

```sh
python3 tests/real_claude/capture.py \
  --out target/compat/audit/tools-new-run \
  --timezone Asia/Shanghai \
  --wrapper target/debug/claude-wrapper \
  --claude target/compat/claude-code-2.1.319/package/claude \
  --probe-proxy http://127.0.0.1:1082 \
  --disable-nonessential --tool-scenario
```

Use a fresh output directory. Tool mode enables permission bypass only for the
fixed commands in this owned fixture and rejects output outside `target/`.
The harness exits nonzero when any tool scenario assertion fails, even if the
actual CLI itself exits zero. `tool-scenario.json` contains checks, actual tool
results, child observations, and runtime asset hashes. Proxy credentials are
never copied into the proof; proxy checks retain booleans only.

The existing `suite.py` covers hidden character triggers, Profile identity,
project environment overrides and a terminal session. Tool mode supplements
that suite. These are bounded client tests, not a guarantee about unknown
future releases, every native entry point, or information in user documents.

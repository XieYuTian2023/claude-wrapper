# TUI checks through a real terminal

Run after building the wrapper:

```sh
python3 tests/tui/pty_ui.py \
  --binary target/debug/claude-wrapper \
  --out target/compat/tui-qa/fresh-run
```

The script creates its own HOME, work directory, Profile directory, and a
fail-only `claude` stub under the output directory. It supplies a clean process
environment. The handoff case saves a default with S, presses Enter on the main
screen, and launches a fresh `start` process. Both launch paths resolve Profiles
relative to the inherited working directory and send their probes to an owned
loopback proxy that rejects them. The check also verifies that Enter restores
the terminal before launch and that `start` leaves the TUI closed. The fixture
prevents client execution and sends no traffic to public services.
For an npm executable entry, pass the installed bin symlink as `--binary`. The
current POSIX entry transfers execution to Rust and needs no Node process. If
testing another Node-based entry, `--node` can add only a symlink inside the
fixture's private PATH. Installed entries also receive the signal and terminal
restoration checks.

The actual TUI receives keyboard input through a controlling PTY. Its stdout
and stderr each have a real terminal, and both raw byte streams are retained.
Checks cover the empty screen, help, preset selection, create/edit/copy/delete,
device ID preservation or regeneration, retained client state, normal quit,
Ctrl+C, and external SIGINT/SIGTERM/SIGHUP. Every terminal attribute is compared
before and after each run, including control characters and input/output speed.
Alternate-screen entry and exit are checked in the raw output.
A small keeper process keeps Darwin's controlling session alive after the UI
exits, until the parent compares terminal attributes. It does not alter the UI's
exit path; without it Darwin revokes the slave before the comparison is possible.

`summary.json` records each result. Case directories contain input/signal logs,
raw `stdout.ansi.bin`/`stderr.ansi.bin`, escape-sequence inventories, exact
terminal attribute snapshots, and numbered screen text files reconstructed from
cursor movement. These text files show content and layout, while raw output
preserves colors and all control bytes. They are terminal captures, not pixel
screenshots or proof of every possible terminal implementation.
`snapshot-index.json` records the exact raw byte prefix for every screen, so a
terminal renderer can replay the matching colors/cells without guessing a frame.
Use `--case management --rows 36 --columns 120` for a focused 120x36 capture;
`--case narrow-80x24` includes both initial and cancelled new-Profile screens.

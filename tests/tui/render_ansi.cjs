"use strict";
// Software terminal interpretation of captured PTY bytes; no native GUI access.
const fs = require("node:fs");
const path = require("node:path");
const crypto = require("node:crypto");
const [input, columns, rows, offsetText, output] = process.argv.slice(2);
if (!output) throw new Error("usage: render_ansi.cjs INPUT COLS ROWS BYTE_OFFSET OUTPUT_JSON");
const modules = process.env.XTERM_NODE_MODULES || path.resolve("target/compat/tui-render-tools/node_modules");
const {Terminal} = require(path.join(modules, "@xterm/headless"));
const version = require(path.join(modules, "@xterm/headless/package.json")).version;
const raw = fs.readFileSync(input);
const offset = Number(offsetText);
if (!Number.isInteger(offset) || offset < 0 || offset > raw.length) throw new Error("invalid captured byte offset");
const terminal = new Terminal({cols: Number(columns), rows: Number(rows), allowProposedApi: true, scrollback: 0});
terminal.write(raw.subarray(0, offset), () => {
  const buffer = terminal.buffer.active;
  const cells = [];
  const text = [];
  for (let y = 0; y < Number(rows); y++) {
    const line = buffer.getLine(buffer.viewportY + y);
    text.push(line.translateToString(true));
    const row = [];
    for (let x = 0; x < Number(columns); x++) {
      const cell = line.getCell(x);
      row.push({chars: cell.getChars(), width: cell.getWidth(), fgMode: cell.getFgColorMode(), fg: cell.getFgColor(),
        bgMode: cell.getBgColorMode(), bg: cell.getBgColor(), bold: Boolean(cell.isBold()),
        italic: Boolean(cell.isItalic()), inverse: Boolean(cell.isInverse()), underline: Boolean(cell.isUnderline()),
        dim: Boolean(cell.isDim())});
    }
    cells.push(row);
  }
  fs.writeFileSync(output, JSON.stringify({kind: "PTY output rendering; not a Terminal window screenshot",
    source: path.resolve(input), sourceSha256: crypto.createHash("sha256").update(raw).digest("hex"),
    capturedBytes: raw.length, snapshotByteOffset: offset, columns: Number(columns), rows: Number(rows),
    interpreter: "@xterm/headless", interpreterVersion: version, activeBuffer: buffer.type, text, cells}, null, 2) + "\n");
  terminal.dispose();
});

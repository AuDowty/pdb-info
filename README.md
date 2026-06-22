# pdb-info

Inspect MSVC PDB symbol databases. Cross-platform.

Pairs with [pe-info](https://github.com/AuDowty/pe-info) — `pe-info` reads what's in the binary, `pdb-info` reads what the compiler knew about it.

## Install

```
cargo install --git https://github.com/AuDowty/pdb-info
```

## Use

```
pdb-info info     foo.pdb
pdb-info symbols  foo.pdb [--filter Substring]
pdb-info modules  foo.pdb
pdb-info sources  foo.pdb
pdb-info lookup   foo.pdb --rva 0x1b520
```

`lookup` is the useful one — feed it an address from a crash dump or profiler and it gives you the symbol + source file/line.

Add `--json` to any subcommand for machine-readable output.

## License

MIT

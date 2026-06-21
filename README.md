# pdb-info

Inspect MSVC PDB symbol databases. Cross-platform — runs on any host (Linux/macOS/Windows).

Pairs naturally with [`pe-info`](https://github.com/AuDowty/pe-info): `pe-info` reads what's in the binary, `pdb-info` reads what the compiler knew about it.

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

`lookup` is the killer feature: feed it a runtime address (from a crash dump, a profiler, or `pe-info exports`) and it tells you the closest symbol plus the source file/line if line info is present.

Add `--json` to any subcommand for machine-readable output:

```
pdb-info symbols foo.pdb --json | jq '.[] | select(.is_function) | .name'
```

## License

MIT.

use std::fs::File;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use pdb::{FallibleIterator, PDB};

#[derive(Parser)]
#[command(name = "pdb-info", version, about = "Inspect MSVC PDB symbol databases")]
struct Cli {
    #[command(subcommand)]
    command: Command,
    #[arg(long, global = true)]
    json: bool,
}

#[derive(Subcommand)]
enum Command {
    Info {
        file: PathBuf,
    },
    Symbols {
        file: PathBuf,
        #[arg(long)]
        filter: Option<String>,
    },
    Modules {
        file: PathBuf,
    },
    Sources {
        file: PathBuf,
    },
    Lookup {
        file: PathBuf,
        #[arg(long, value_parser = parse_hex)]
        rva: u32,
    },
}

fn parse_hex(s: &str) -> Result<u32, String> {
    let s = s.trim_start_matches("0x").trim_start_matches("0X");
    u32::from_str_radix(s, 16).map_err(|e| format!("not a hex u32: {e}"))
}

fn main() -> ExitCode {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let msg = info
            .payload()
            .downcast_ref::<String>()
            .map(|s| s.as_str())
            .or_else(|| info.payload().downcast_ref::<&str>().copied())
            .unwrap_or("");
        if msg.contains("failed printing to stdout") {
            std::process::exit(0);
        }
        default_hook(info);
    }));
    let cli = Cli::parse();
    let result = match &cli.command {
        Command::Info { file } => info(file, cli.json),
        Command::Symbols { file, filter } => symbols(file, cli.json, filter.as_deref()),
        Command::Modules { file } => modules(file, cli.json),
        Command::Sources { file } => sources(file, cli.json),
        Command::Lookup { file, rva } => lookup(file, cli.json, *rva),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn open(file: &PathBuf) -> Result<PDB<'static, File>, String> {
    let f = File::open(file).map_err(|e| format!("open {}: {e}", file.display()))?;
    PDB::open(f).map_err(|e| format!("parse {}: {e}", file.display()))
}

fn info(file: &PathBuf, json: bool) -> Result<(), String> {
    let mut pdb = open(file)?;
    let pi = pdb.pdb_information().map_err(|e| e.to_string())?;
    let dbi = pdb.debug_information().map_err(|e| e.to_string())?;
    let machine = dbi.machine_type().ok().map(|m| format!("{m:?}"));
    let symbol_count = {
        let mut n: u64 = 0;
        let table = pdb.global_symbols().map_err(|e| e.to_string())?;
        let mut iter = table.iter();
        while iter.next().map_err(|e| e.to_string())?.is_some() {
            n += 1;
        }
        n
    };
    if json {
        let v = serde_json::json!({
            "guid": pi.guid.as_hyphenated().to_string(),
            "age": pi.age,
            "signature": pi.signature,
            "machine_type": machine,
            "global_symbols": symbol_count,
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        println!("guid:            {}", pi.guid.as_hyphenated());
        println!("age:             {}", pi.age);
        println!("signature:       {}", pi.signature);
        if let Some(m) = machine {
            println!("machine:         {m}");
        }
        println!("global symbols:  {symbol_count}");
    }
    Ok(())
}

fn symbols(file: &PathBuf, json: bool, filter: Option<&str>) -> Result<(), String> {
    let mut pdb = open(file)?;
    let address_map = pdb.address_map().map_err(|e| e.to_string())?;
    let table = pdb.global_symbols().map_err(|e| e.to_string())?;
    let mut iter = table.iter();
    let mut out: Vec<(String, u32, bool, bool)> = Vec::new();
    while let Some(sym) = iter.next().map_err(|e| e.to_string())? {
        if let Ok(pdb::SymbolData::Public(d)) = sym.parse() {
            let name = d.name.to_string().into_owned();
            if let Some(f) = filter {
                if !name.contains(f) {
                    continue;
                }
            }
            let rva = d.offset.to_rva(&address_map).map(|r| r.0).unwrap_or(0);
            out.push((name, rva, d.function, d.code));
        }
    }
    out.sort_by_key(|(_, rva, _, _)| *rva);
    if json {
        let arr: Vec<_> = out
            .iter()
            .map(|(name, rva, is_fn, is_code)| {
                serde_json::json!({
                    "name": name,
                    "rva": format!("0x{rva:08x}"),
                    "is_function": is_fn,
                    "is_code": is_code,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap());
    } else {
        println!("{:<12}  KIND  NAME", "RVA");
        for (name, rva, is_fn, is_code) in &out {
            let kind = if *is_fn {
                "FUNC"
            } else if *is_code {
                "CODE"
            } else {
                "DATA"
            };
            println!("0x{rva:08x}  {kind}  {name}");
        }
    }
    Ok(())
}

fn modules(file: &PathBuf, json: bool) -> Result<(), String> {
    let mut pdb = open(file)?;
    let dbi = pdb.debug_information().map_err(|e| e.to_string())?;
    let mut iter = dbi.modules().map_err(|e| e.to_string())?;
    let mut out: Vec<(String, String)> = Vec::new();
    while let Some(m) = iter.next().map_err(|e| e.to_string())? {
        let name = m.module_name().into_owned();
        let obj = m.object_file_name().into_owned();
        out.push((name, obj));
    }
    if json {
        let arr: Vec<_> = out
            .iter()
            .map(|(n, o)| {
                serde_json::json!({
                    "name": n,
                    "object_file": o,
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap());
    } else {
        for (n, o) in &out {
            if n == o || o.is_empty() {
                println!("{n}");
            } else {
                println!("{n}  ({o})");
            }
        }
    }
    Ok(())
}

fn sources(file: &PathBuf, json: bool) -> Result<(), String> {
    let mut pdb = open(file)?;
    let string_table = pdb.string_table().map_err(|e| e.to_string())?;
    let dbi = pdb.debug_information().map_err(|e| e.to_string())?;
    let mut mods = dbi.modules().map_err(|e| e.to_string())?;
    let mut seen: std::collections::BTreeSet<String> = Default::default();
    while let Some(m) = mods.next().map_err(|e| e.to_string())? {
        let Some(mi) = pdb.module_info(&m).map_err(|e| e.to_string())? else {
            continue;
        };
        let lp = match mi.line_program() {
            Ok(lp) => lp,
            Err(_) => continue,
        };
        let mut files = lp.files();
        while let Some(f) = files.next().map_err(|e| e.to_string())? {
            if let Ok(name) = string_table.get(f.name) {
                seen.insert(name.to_string().into_owned());
            }
        }
    }
    if json {
        let arr: Vec<_> = seen.iter().collect();
        println!("{}", serde_json::to_string_pretty(&arr).unwrap());
    } else {
        for s in &seen {
            println!("{s}");
        }
    }
    Ok(())
}

fn lookup(file: &PathBuf, json: bool, rva_query: u32) -> Result<(), String> {
    let mut pdb = open(file)?;
    let address_map = pdb.address_map().map_err(|e| e.to_string())?;

    let table = pdb.global_symbols().map_err(|e| e.to_string())?;
    let mut iter = table.iter();
    let mut best: Option<(String, u32)> = None;
    while let Some(sym) = iter.next().map_err(|e| e.to_string())? {
        if let Ok(pdb::SymbolData::Public(d)) = sym.parse() {
            if let Some(rva) = d.offset.to_rva(&address_map) {
                if rva.0 <= rva_query
                    && best.as_ref().map(|(_, r)| rva.0 > *r).unwrap_or(true)
                {
                    best = Some((d.name.to_string().into_owned(), rva.0));
                }
            }
        }
    }

    let string_table = pdb.string_table().ok();
    let dbi = pdb.debug_information().map_err(|e| e.to_string())?;
    let mut mods = dbi.modules().map_err(|e| e.to_string())?;
    let mut source: Option<(String, u32)> = None;
    'outer: while let Some(m) = mods.next().map_err(|e| e.to_string())? {
        let Some(mi) = pdb.module_info(&m).map_err(|e| e.to_string())? else {
            continue;
        };
        let lp = match mi.line_program() {
            Ok(lp) => lp,
            Err(_) => continue,
        };
        let mut lines = lp.lines();
        while let Some(line) = lines.next().map_err(|e| e.to_string())? {
            if let Some(rva) = line.offset.to_rva(&address_map) {
                let length = line.length.unwrap_or(0);
                if rva_query >= rva.0 && rva_query < rva.0.saturating_add(length).max(rva.0 + 1) {
                    if let (Ok(file_info), Some(st)) =
                        (lp.get_file_info(line.file_index), string_table.as_ref())
                    {
                        if let Ok(name) = st.get(file_info.name) {
                            source =
                                Some((name.to_string().into_owned(), line.line_start));
                            break 'outer;
                        }
                    }
                }
            }
        }
    }

    if json {
        let v = serde_json::json!({
            "rva": format!("0x{rva_query:08x}"),
            "symbol": best.as_ref().map(|(n, r)| serde_json::json!({
                "name": n,
                "rva": format!("0x{r:08x}"),
                "offset_into": rva_query - r,
            })),
            "source": source.as_ref().map(|(f, l)| serde_json::json!({
                "file": f,
                "line": l,
            })),
        });
        println!("{}", serde_json::to_string_pretty(&v).unwrap());
    } else {
        println!("rva:    0x{rva_query:08x}");
        if let Some((n, r)) = &best {
            println!("symbol: {n}");
            println!("        at 0x{r:08x} (+{} bytes)", rva_query - r);
        } else {
            println!("symbol: (none found)");
        }
        if let Some((f, l)) = &source {
            println!("source: {f}:{l}");
        } else {
            println!("source: (no line info)");
        }
    }
    Ok(())
}

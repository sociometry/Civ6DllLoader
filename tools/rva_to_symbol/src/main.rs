use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::Path;
use std::process;

#[derive(Debug, serde::Deserialize)]
struct Entry {
    kind: String,
    demangled: String,
    mangled: String,
    vtable_xrefs: Vec<String>,
}

const USAGE: &str = r#"rva_to_symbol - query RVA symbol info from rva_map.json

USAGE:
    rva_to_symbol [FLAGS] <RVA>...
    rva_to_symbol [FLAGS] {<RVA>,<RVA>...}...
    rva_to_symbol [FLAGS] rva <RVA>...
    rva_to_symbol rva [FLAGS] <RVA>...
    rva_to_symbol -h | --help
    rva_to_symbol --version

POSITIONAL ARGUMENTS:
    <RVA>            Hex RVA, optional 0x/0X prefix (e.g. 0xA130, a130,
                     0X9bade0). Normalized to lowercase "0x"+digits (leading
                     zeros are preserved) and used as the exact key.
    {<RVA>,<RVA>}    Group of RVAs in a single argument, comma-separated.
                     Whitespace around each element is trimmed; an empty
                     element is an error.
    rva              If the first positional argument is exactly "rva", it is
                     ignored. This allows the invocation form "rva <RVA>...".

FLAGS (field selectors; any combination, any position):
    --kind           Output only the kind field.
    --demangled      Output only the demangled field.
    --mangled        Output only the mangled field.
    --vtable_xrefs   Output only the vtable_xrefs field.
    -h, --help       Print this help to stdout and exit 0.
    --version        Print "rva_to_symbol <version>" to stdout and exit 0.

OUTPUT:
    One section per query target, in input order, with no blank lines between
    sections. The first line of a section is the normalized RVA. Then one line
    per selected field in the fixed order kind, demangled, mangled,
    vtable_xrefs, each formatted as "  <label>:" left-aligned to width 15
    followed by the value (so values start at column 17). With no field
    selector, all four fields are printed. vtable_xrefs is printed as
    "[elem1, elem2]" (an empty list as "[]"). An RVA not present in
    rva_map.json prints a single line "<rva>: not found".

EXIT CODES:
    0    every target was found
    1    at least one target was not found (found targets still print)
    2    usage/argument error, or rva_map.json could not be read/parsed

rva_map.json is looked up next to the executable (std::env::current_exe()),
not in the current working directory.
"#;

fn main() {
    // Data loading happens at startup: rva_map.json lives next to the exe.
    let map: HashMap<String, Entry> = load_map();

    let args: Vec<String> = env::args().skip(1).collect();

    let mut positionals: Vec<String> = Vec::new();
    let mut f_kind = false;
    let mut f_demangled = false;
    let mut f_mangled = false;
    let mut f_xrefs = false;

    for a in &args {
        if a.starts_with('-') {
            match a.as_str() {
                "--kind" => f_kind = true,
                "--demangled" => f_demangled = true,
                "--mangled" => f_mangled = true,
                "--vtable_xrefs" => f_xrefs = true,
                "-h" | "--help" => {
                    print!("{}", USAGE);
                    process::exit(0);
                }
                "--version" => {
                    println!("rva_to_symbol {}", env!("CARGO_PKG_VERSION"));
                    process::exit(0);
                }
                _ => {
                    eprintln!("error: unknown flag: {}", a);
                    process::exit(2);
                }
            }
        } else {
            positionals.push(a.clone());
        }
    }

    // Optional literal "rva" prefix on the first positional argument.
    if positionals.first().map(String::as_str) == Some("rva") {
        positionals.remove(0);
    }

    if positionals.is_empty() {
        eprint!("{}", USAGE);
        process::exit(2);
    }

    // Expand {} groups, then normalize every token.
    let mut queries: Vec<String> = Vec::new();
    for t in &positionals {
        if t.starts_with('{') {
            if !t.ends_with('}') {
                eprintln!("error: malformed group: {}", t);
                process::exit(2);
            }
            let inner = &t[1..t.len() - 1];
            if inner.is_empty() {
                eprintln!("error: empty group: {}", t);
                process::exit(2);
            }
            for part in inner.split(',') {
                let p = part.trim();
                if p.is_empty() {
                    eprintln!("error: empty element in group: {}", t);
                    process::exit(2);
                }
                queries.push(p.to_string());
            }
        } else {
            queries.push(t.clone());
        }
    }

    let mut norm: Vec<String> = Vec::with_capacity(queries.len());
    for q in &queries {
        match normalize_rva(q) {
            Ok(n) => norm.push(n),
            Err(e) => {
                eprintln!("{}", e);
                process::exit(2);
            }
        }
    }

    let any_selector = f_kind || f_demangled || f_mangled || f_xrefs;
    let mut miss = false;

    for rva in &norm {
        match map.get(rva) {
            Some(e) => {
                println!("{}", rva);
                if !any_selector || f_kind {
                    println!("  {:<15}{}", "kind:", e.kind);
                }
                if !any_selector || f_demangled {
                    println!("  {:<15}{}", "demangled:", e.demangled);
                }
                if !any_selector || f_mangled {
                    println!("  {:<15}{}", "mangled:", e.mangled);
                }
                if !any_selector || f_xrefs {
                    println!("  {:<15}{}", "vtable_xrefs:", fmt_xrefs(&e.vtable_xrefs));
                }
            }
            None => {
                println!("{}: not found", rva);
                miss = true;
            }
        }
    }

    process::exit(if miss { 1 } else { 0 });
}

fn normalize_rva(tok: &str) -> Result<String, String> {
    let rest = tok
        .strip_prefix("0x")
        .or_else(|| tok.strip_prefix("0X"))
        .unwrap_or(tok);
    if rest.is_empty() || !rest.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(format!("error: invalid RVA: {}", tok));
    }
    Ok(format!("0x{}", rest.to_ascii_lowercase()))
}

fn fmt_xrefs(xs: &[String]) -> String {
    if xs.is_empty() {
        return "[]".to_string();
    }
    format!("[{}]", xs.join(", "))
}

fn load_map() -> HashMap<String, Entry> {
    let exe = env::current_exe().unwrap_or_else(|_| {
        eprintln!("error: cannot read rva_map.json");
        process::exit(2);
    });
    let dir = exe.parent().unwrap_or_else(|| Path::new("."));
    let path = dir.join("rva_map.json");
    let text = fs::read_to_string(&path).unwrap_or_else(|_| {
        eprintln!("error: cannot read rva_map.json");
        process::exit(2);
    });
    let raw: HashMap<String, Entry> = serde_json::from_str(&text).unwrap_or_else(|_| {
        eprintln!("error: cannot read rva_map.json");
        process::exit(2);
    });
    // Keys in the real rva_map.json keep their original hex casing (e.g.
    // "0xA130", "0x9BADE0"); lowercase them so the spec-mandated lowercase
    // normalization + exact key lookup matches (bijective: no collisions).
    raw.into_iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect()
}

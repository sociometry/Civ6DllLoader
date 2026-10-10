use std::collections::HashMap;
use std::env;
use std::process;

#[derive(Debug, serde::Deserialize)]
struct Entry {
    kind: String,
    demangled: String,
    mangled: String,
    vtable_xrefs: Vec<String>,
}

/// 编译期嵌入的符号表（zlib 压缩）。
///
/// 三个映像的 JSON 原始体积合计约 30 MB，压缩后约 2.7 MB，因此直接用
/// include_bytes! 打进 .rdata：交付物保持单个 exe，不需要任何 sidecar 文件。
/// 查询时**只解压并解析选中的那一份**，另外两份始终是字节数组，不产生
/// 任何解码/分配开销。
///
/// 用 zlib 而非 lzma：lzma 能再小 1 MB，但纯 Rust 解码慢 4-5 倍（~120 ms vs
/// ~25 ms），对每次查表都要走一遍启动路径的 cli 来说不划算。
///
/// 数据由 tools/gen_rva_map.py 生成（改了 symdb JSON 之后要重新生成并重编译）。
const GAMECORE_Z: &[u8] = include_bytes!("../data/rva_map.gamecore.z");
const DX11_Z: &[u8] = include_bytes!("../data/rva_map.dx11.z");
const DX12_Z: &[u8] = include_bytes!("../data/rva_map.dx12.z");

/// 一个可查询的映像。
struct Image {
    /// 命令行选择符（不含前导横线），大小写不敏感。
    selector: &'static str,
    /// 与 loader 的 HookImageId 对应的数值，仅用于输出。
    image_id: u32,
    /// 展示名。
    label: &'static str,
    /// 对应的符号表 JSON 文件名，仅用于输出。
    source: &'static str,
    data: &'static [u8],
}

const IMAGES: &[Image] = &[
    Image {
        selector: "gamecore",
        image_id: 5,
        label: "GameCoreXP2",
        source: "GameCore.symdb.json",
        data: GAMECORE_Z,
    },
    Image {
        selector: "dx11",
        image_id: 1,
        label: "ExeDx11",
        source: "CivilizationVI.symdb.json",
        data: DX11_Z,
    },
    Image {
        selector: "dx12",
        image_id: 2,
        label: "ExeDx12",
        source: "CivilizationVI_DX12.symdb.json",
        data: DX12_Z,
    },
];

const USAGE: &str = r#"rva_to_symbol - query symbol info for an RVA of a Civ6 image

USAGE:
    rva_to_symbol <IMAGE> [FLAGS] <RVA>...
    rva_to_symbol <IMAGE> [FLAGS] {<RVA>,<RVA>...}...
    rva_to_symbol <IMAGE> [FLAGS] rva <RVA>...
    rva_to_symbol -h | --help
    rva_to_symbol --version
    rva_to_symbol --list

IMAGE (exactly one is required; the three images have unrelated RVAs, so a
default would silently give wrong answers):
    -gamecore        GameCore_XP2_FinalRelease.dll (image 5)
    -dx11            CivilizationVI.exe           (image 1)
    -dx12            CivilizationVI_DX12.exe      (image 2)
                     Also accepted as --gamecore etc.

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
    --list           List the embeddable images and exit 0.

OUTPUT:
    One section per query target, in input order, with no blank lines between
    sections. The first line of a section is the normalized RVA. Then one line
    per selected field in the fixed order kind, demangled, mangled,
    vtable_xrefs, each formatted as "  <label>:" left-aligned to width 15
    followed by the value (so values start at column 17). With no field
    selector, all four fields are printed. vtable_xrefs is printed as
    "[elem1, elem2]" (an empty list as "[]"). An RVA not present in the
    selected image prints a single line "<rva>: not found".

EXIT CODES:
    0    every target was found
    1    at least one target was not found (found targets still print)
    2    usage/argument error, or the embedded symbol table could not be
         decoded

The symbol tables are embedded in the executable (zlib-compressed), so this
tool is a single self-contained file; only the selected image is decoded.
"#;

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();

    let mut positionals: Vec<String> = Vec::new();
    let mut f_kind = false;
    let mut f_demangled = false;
    let mut f_mangled = false;
    let mut f_xrefs = false;
    let mut images: Vec<&'static Image> = Vec::new();

    for a in &args {
        if a.starts_with('-') {
            // 长短横线都接受；先按原样匹配已知的短横线 flag。
            match a.as_str() {
                "--kind" => {
                    f_kind = true;
                    continue;
                }
                "--demangled" => {
                    f_demangled = true;
                    continue;
                }
                "--mangled" => {
                    f_mangled = true;
                    continue;
                }
                "--vtable_xrefs" => {
                    f_xrefs = true;
                    continue;
                }
                "-h" | "--help" => {
                    print!("{}", USAGE);
                    process::exit(0);
                }
                "--version" => {
                    println!("rva_to_symbol {}", env!("CARGO_PKG_VERSION"));
                    process::exit(0);
                }
                "--list" => {
                    for img in IMAGES {
                        println!(
                            "-{:<9} image={}  {:<14} {}",
                            img.selector, img.image_id, img.label, img.source
                        );
                    }
                    process::exit(0);
                }
                _ => {}
            }
            // 映像选择符：-gamecore / --gamecore / -GameCore 都收。
            let bare = a.trim_start_matches('-').to_ascii_lowercase();
            match IMAGES.iter().find(|i| i.selector == bare) {
                Some(img) => images.push(img),
                None => {
                    eprintln!("error: unknown flag: {}", a);
                    eprintln!("hint: image must be one of -gamecore, -dx11, -dx12");
                    process::exit(2);
                }
            }
        } else {
            positionals.push(a.clone());
        }
    }

    // 必须且只能指定一个映像：三份符号表的 RVA 互不相关，猜一个必然给出错误答案。
    if images.is_empty() {
        eprintln!("error: no image specified");
        eprintln!("hint: pass exactly one of -gamecore, -dx11, -dx12");
        process::exit(2);
    }
    if images.len() > 1 {
        eprintln!("error: more than one image specified");
        eprintln!("hint: pass exactly one of -gamecore, -dx11, -dx12");
        process::exit(2);
    }
    let image = images[0];

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

    // 只解码选中的映像。
    let map = load_image(image);

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

/// 解压并解析选中的映像符号表。
fn load_image(image: &Image) -> HashMap<String, Entry> {
    let mut json = Vec::new();
    if zlib_decode(&mut &image.data[..], &mut json).is_err() {
        eprintln!(
            "error: cannot decode embedded symbol table for {} ({})",
            image.selector, image.source
        );
        process::exit(2);
    }
    let raw: HashMap<String, Entry> = serde_json::from_slice(&json).unwrap_or_else(|_| {
        eprintln!(
            "error: cannot parse embedded symbol table for {} ({})",
            image.selector, image.source
        );
        process::exit(2);
    });
    // 键在生成端是 "0x<大写>"；统一小写以配合 normalize_rva 的小写归一化做精确查表。
    raw.into_iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect()
}

/// zlib 解压（flate2 默认走纯 Rust 的 miniz_oxide，无 C 依赖）。
fn zlib_decode(r: &mut dyn std::io::Read, w: &mut Vec<u8>) -> std::io::Result<()> {
    let mut d = flate2::read::ZlibDecoder::new(r);
    std::io::copy(&mut d, w)?;
    Ok(())
}

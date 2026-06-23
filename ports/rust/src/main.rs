//! AGENTTAX CLI — Rust port. Mirrors `agenttax classify` + `taxonomy`.
//! Passive, offline, no network.

use agenttax::*;
use std::process::exit;

fn band_label(b: &str) -> &'static str {
    match b {
        "high" => "HIGH",
        "medium" => "MED ",
        "low" => "LOW ",
        _ => "----",
    }
}

fn render_table(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "AGENTTAX — AI-agent threat taxonomy mapping  (source: {})\n",
        report.source
    ));
    out.push_str(&"=".repeat(74));
    out.push('\n');
    if report.classifications.is_empty() {
        out.push_str("No findings to classify.\n");
        return out;
    }
    for cl in &report.classifications {
        let mut head = cl.id.clone();
        if !cl.title.is_empty() {
            head.push_str(&format!(": {}", cl.title));
        }
        out.push_str(&head);
        out.push('\n');
        let snip = if cl.text.chars().count() <= 100 {
            cl.text.clone()
        } else {
            let s: String = cl.text.chars().take(97).collect();
            format!("{}...", s)
        };
        out.push_str(&format!("    \"{}\"\n", snip));
        if cl.matches.is_empty() {
            out.push_str("    [----] no taxonomy category matched (review manually)\n");
        }
        for m in &cl.matches {
            out.push_str(&format!(
                "    [{}] {}  (conf {:.2}, {})\n",
                band_label(&m.band),
                m.label,
                m.confidence,
                m.reference
            ));
            out.push_str(&format!("           mitigation: {}\n", m.mitigation));
        }
        out.push('\n');
    }
    let counts = category_counts(report);
    let uncl = unclassified(report);
    let classified = report.classifications.len() - uncl;
    out.push_str(&"-".repeat(74));
    out.push('\n');
    let mut bits: Vec<String> = Vec::new();
    for cat in taxonomy() {
        if let Some(&n) = counts.get(cat.id) {
            if n > 0 {
                let head = cat.id.split('_').next().unwrap_or(cat.id).to_lowercase();
                bits.push(format!("{}={}", head, n));
            }
        }
    }
    let cat_str = if bits.is_empty() {
        "none".to_string()
    } else {
        bits.join(", ")
    };
    let highest = report
        .classifications
        .iter()
        .map(|c| c.top_band.clone())
        .min_by_key(|b| match b.as_str() {
            "high" => 0,
            "medium" => 1,
            "low" => 2,
            _ => 3,
        })
        .unwrap_or_else(|| "none".to_string());
    out.push_str(&format!(
        "findings={}  classified={}  unclassified={}\n",
        report.classifications.len(),
        classified,
        uncl
    ));
    out.push_str(&format!("category hits: {}\n", cat_str));
    out.push_str(&format!("highest confidence: {}", highest));
    out
}

fn render_taxonomy() -> String {
    let mut out = String::new();
    out.push_str("AGENTTAX — Microsoft AI-agent threat taxonomy (7 categories)\n");
    out.push_str(&"=".repeat(74));
    out.push('\n');
    for c in taxonomy() {
        out.push_str(&format!("{}  [{}]\n", c.id, c.reference));
        out.push_str(&format!("    {}\n", c.label));
        out.push_str(&format!("    {}\n", c.description));
        out.push_str(&format!("    mitigation: {}\n", c.mitigation));
        out.push_str(&format!("    signals: {}\n\n", c.signals.len()));
    }
    out.trim_end().to_string()
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    exit(run(&argv));
}

fn run(argv: &[String]) -> i32 {
    if argv.iter().any(|a| a == "--version") {
        println!("{} {}", TOOL_NAME, TOOL_VERSION);
        return 0;
    }
    if argv.is_empty() {
        eprintln!("usage: {} {{classify,taxonomy}} [...]", TOOL_NAME);
        return 2;
    }
    match argv[0].as_str() {
        "taxonomy" => {
            println!("{}", render_taxonomy());
            0
        }
        "classify" => {
            let mut text: Option<String> = None;
            let mut path: Option<String> = None;
            let mut fail_on = "none".to_string();
            let mut min_conf = 0.0_f64;
            let mut i = 1;
            while i < argv.len() {
                match argv[i].as_str() {
                    "--text" if i + 1 < argv.len() => {
                        i += 1;
                        text = Some(argv[i].clone());
                    }
                    "--fail-on" if i + 1 < argv.len() => {
                        i += 1;
                        fail_on = argv[i].clone();
                    }
                    "--min-confidence" if i + 1 < argv.len() => {
                        i += 1;
                        min_conf = argv[i].parse().unwrap_or(0.0);
                    }
                    // --format / --out accepted for CLI-compat; table is emitted.
                    "--format" | "--out" if i + 1 < argv.len() => {
                        i += 1;
                    }
                    a if !a.starts_with("--") && path.is_none() => {
                        path = Some(a.to_string());
                    }
                    _ => {}
                }
                i += 1;
            }

            let findings = if let Some(t) = text {
                findings_from_text(&t)
            } else if let Some(p) = path {
                match std::fs::read_to_string(&p) {
                    Ok(raw) => parse_findings(&raw),
                    Err(e) => {
                        eprintln!("error: {}", e);
                        return 2;
                    }
                }
            } else {
                eprintln!("error: provide a findings file or --text");
                return 2;
            };

            let mc = min_conf.clamp(0.0, 1.0);
            let report = classify_findings(&findings, mc);
            println!("{}", render_table(&report));
            if fail_triggered(&report, &fail_on) {
                1
            } else {
                0
            }
        }
        _ => {
            eprintln!("usage: {} {{classify,taxonomy}} [...]", TOOL_NAME);
            2
        }
    }
}

/// Minimal findings parser: pulls each finding's text fields out of the demo
/// JSON shape without an external JSON dependency. Supports `{"findings":[...]}`
/// and a top-level array; objects are scanned for the standard text keys.
fn parse_findings(raw: &str) -> Vec<Finding> {
    // Strip to the findings array if wrapped in an object.
    let body = if let Some(idx) = raw.find("\"findings\"") {
        &raw[idx..]
    } else {
        raw
    };
    let start = body.find('[').map(|i| i + 1).unwrap_or(0);
    let mut out: Vec<Finding> = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in body[start..].chars() {
        match ch {
            '{' => {
                depth += 1;
                cur.push(ch);
            }
            '}' => {
                depth -= 1;
                cur.push(ch);
                if depth == 0 {
                    let obj = cur.clone();
                    let id = extract(&obj, "id").unwrap_or_else(|| format!("F{}", out.len() + 1));
                    let title = extract(&obj, "title")
                        .or_else(|| extract(&obj, "name"))
                        .unwrap_or_default();
                    let mut parts: Vec<String> = Vec::new();
                    for k in ["title", "name", "description", "text", "message", "detail", "summary", "observation"] {
                        if let Some(v) = extract(&obj, k) {
                            parts.push(v);
                        }
                    }
                    out.push(Finding {
                        id,
                        title,
                        text: parts.join(" ").trim().to_string(),
                    });
                    cur.clear();
                }
            }
            ']' if depth == 0 => break,
            _ if depth > 0 => cur.push(ch),
            _ => {}
        }
    }
    out
}

/// Extract a string value for a JSON key from a small object slice.
fn extract(obj: &str, key: &str) -> Option<String> {
    let needle = format!("\"{}\"", key);
    let kpos = obj.find(&needle)?;
    let after = &obj[kpos + needle.len()..];
    let colon = after.find(':')?;
    let rest = after[colon + 1..].trim_start();
    if !rest.starts_with('"') {
        return None;
    }
    let mut val = String::new();
    let mut escaped = false;
    for ch in rest[1..].chars() {
        if escaped {
            match ch {
                'n' => val.push('\n'),
                't' => val.push('\t'),
                other => val.push(other),
            }
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            break;
        } else {
            val.push(ch);
        }
    }
    Some(val)
}

mod common;

use common::prompt_choice;
use flate2::read::GzDecoder;
use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::path::Path;

struct TableData {
    columns: Vec<String>,
    rows: Vec<Vec<String>>,
}

fn parse_tables(path: &Path) -> BTreeMap<String, TableData> {
    let file = std::fs::File::open(path).expect("Failed to open backup file");
    let decoder = GzDecoder::new(file);
    let reader = BufReader::new(decoder);

    let mut tables: BTreeMap<String, TableData> = BTreeMap::new();
    let mut current_table: Option<String> = None;
    let mut current_columns: Vec<String> = Vec::new();

    for line in reader.lines() {
        let line = match line {
            Ok(l) => l,
            Err(_) => continue,
        };

        if line.starts_with("COPY ") && line.contains(" FROM stdin;") {
            let after_copy = &line[5..];
            let paren_start = after_copy.find('(');
            let paren_end = after_copy.find(')');

            if let (Some(ps), Some(pe)) = (paren_start, paren_end) {
                let table_name = after_copy[..ps].trim().to_string();
                let cols_str = &after_copy[ps + 1..pe];
                let columns: Vec<String> = cols_str.split(',').map(|c| c.trim().to_string()).collect();
                current_columns = columns;
                current_table = Some(table_name);

                tables.entry(current_table.clone().unwrap()).or_insert_with(|| TableData {
                    columns: current_columns.clone(),
                    rows: Vec::new(),
                });
            }
        } else if line == "\\." {
            current_table = None;
            current_columns.clear();
        } else if current_table.is_some() {
            let table_name = current_table.as_ref().unwrap();
            let values: Vec<String> = line.split('\t').map(|v| v.to_string()).collect();
            if let Some(table) = tables.get_mut(table_name) {
                table.rows.push(values);
            }
        }
    }

    tables
}

fn print_table(name: &str, data: &TableData) {
    println!("\n── {} ({} rows) ──\n", name, data.rows.len());

    if data.rows.is_empty() {
        println!("(empty table)");
        return;
    }

    let mut widths: Vec<usize> = data.columns.iter().map(|c| c.len()).collect();
    for row in &data.rows {
        for (i, val) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(val.len().min(40));
            }
        }
    }

    let header: Vec<String> = data
        .columns
        .iter()
        .enumerate()
        .map(|(i, c)| format!("{:width$}", c, width = widths.get(i).copied().unwrap_or(10)))
        .collect();
    println!("{}", header.join(" | "));
    let separator: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
    println!("{}", separator.join("-+-"));

    for row in &data.rows {
        let formatted: Vec<String> = row
            .iter()
            .enumerate()
            .map(|(i, v)| {
                let w = widths.get(i).copied().unwrap_or(10);
                let truncated = if v.len() > 40 {
                    format!("{}…", &v[..39])
                } else {
                    v.clone()
                };
                format!("{:width$}", truncated, width = w)
            })
            .collect();
        println!("{}", formatted.join(" | "));
    }
}

fn main() {
    let backup_dir = std::env::args().nth(1).unwrap_or_else(|| "backups".to_string());
    let base = std::path::Path::new(&backup_dir);

    if !base.exists() {
        eprintln!("Backup directory '{}' not found", backup_dir);
        std::process::exit(1);
    }

    let (_, backup_path) = match common::select_backup(base) {
        Some(v) => v,
        None => return,
    };

    println!("\nParsing {}...", backup_path.display());
    let tables = parse_tables(&backup_path);

    if tables.is_empty() {
        println!("No tables with data found in this backup.");
        return;
    }

    loop {
        let table_names: Vec<String> = tables
            .iter()
            .map(|(name, data)| format!("{} ({} rows)", name, data.rows.len()))
            .collect();
        let raw_names: Vec<String> = tables.keys().cloned().collect();

        let table_idx = match prompt_choice("Select table (Ctrl+C to quit):", &table_names) {
            Some(i) => i,
            None => continue,
        };

        let name = &raw_names[table_idx];
        print_table(name, &tables[name]);
    }
}

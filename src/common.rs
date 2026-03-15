use std::io::{self, Write};
use std::path::{Path, PathBuf};

pub fn prompt_choice(prompt: &str, options: &[String]) -> Option<usize> {
    if options.is_empty() {
        println!("No items found.");
        return None;
    }
    println!("\n{}", prompt);
    for (i, opt) in options.iter().enumerate() {
        println!("  [{}] {}", i + 1, opt);
    }
    print!("\nSelect (1-{}): ", options.len());
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let idx: usize = input.trim().parse().ok()?;
    if idx >= 1 && idx <= options.len() {
        Some(idx - 1)
    } else {
        None
    }
}

pub fn prompt_confirm(message: &str) -> bool {
    print!("\n{} [y/N]: ", message);
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    matches!(input.trim().to_lowercase().as_str(), "y" | "yes")
}

pub fn list_backups(base: &Path) -> Vec<(String, Vec<(String, PathBuf)>)> {
    let mut result = Vec::new();
    let mut dirs: Vec<_> = std::fs::read_dir(base)
        .expect("Failed to read backups directory")
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    dirs.sort_by_key(|e| e.file_name());

    for dir in dirs {
        let container_name = dir.file_name().to_string_lossy().to_string();
        let mut files: Vec<(String, PathBuf)> = std::fs::read_dir(dir.path())
            .into_iter()
            .flatten()
            .filter_map(|e| e.ok())
            .filter(|e| {
                e.path()
                    .extension()
                    .map(|ext| ext == "gz")
                    .unwrap_or(false)
            })
            .map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                (name, e.path())
            })
            .collect();
        files.sort_by(|a, b| b.0.cmp(&a.0));
        if !files.is_empty() {
            result.push((container_name, files));
        }
    }
    result
}

pub fn select_backup(base: &Path) -> Option<(String, PathBuf)> {
    let backups = list_backups(base);
    if backups.is_empty() {
        println!("No backups found in '{}'", base.display());
        return None;
    }

    let container_names: Vec<String> = backups.iter().map(|(name, _)| name.clone()).collect();
    let container_idx = prompt_choice("Select container:", &container_names)?;
    let (container_name, files) = &backups[container_idx];

    let file_names: Vec<String> = files.iter().map(|(name, _)| name.clone()).collect();
    let file_idx = prompt_choice(&format!("Backups for '{}':", container_name), &file_names)?;
    let (_, backup_path) = &files[file_idx];

    Some((container_name.clone(), backup_path.clone()))
}

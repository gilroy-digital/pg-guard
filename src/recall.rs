mod common;

use std::collections::BTreeSet;
use std::io::Read;
use std::process::{Command, Stdio};

fn run_psql(container: &str, user: &str, password: &str, db: &str, sql: &[u8]) -> bool {
    let mut child = Command::new("docker")
        .arg("exec")
        .arg("-i")
        .arg("-e")
        .arg(format!("PGPASSWORD={}", password))
        .arg(container)
        .args(["psql", "-U", user, "-d", db, "--set", "ON_ERROR_STOP=off"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("Failed to start docker exec");

    {
        let stdin = child.stdin.as_mut().expect("Failed to open stdin");
        if let Err(e) = std::io::Write::write_all(stdin, sql) {
            drop(child.stdin.take());
            let output = child.wait_with_output().expect("Failed to wait for psql");
            eprintln!("Write error: {}", e);
            eprintln!("psql stderr:\n{}", String::from_utf8_lossy(&output.stderr));
            return false;
        }
    }

    let output = child.wait_with_output().expect("Failed to wait for psql");
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.is_empty() {
        eprintln!("{}", stderr);
    }
    output.status.success()
}

fn main() {
    let backup_dir = std::env::args().nth(1).unwrap_or_else(|| "backups".to_string());
    let base = std::path::Path::new(&backup_dir);

    if !base.exists() {
        eprintln!("Backup directory '{}' not found", backup_dir);
        std::process::exit(1);
    }

    let (container_name, backup_path) = match common::select_backup(base) {
        Some(v) => v,
        None => return,
    };

    println!("\nBackup: {}", backup_path.display());
    println!("Target: {}", container_name);

    if !common::prompt_confirm(&format!(
        "WARNING: This will DROP and recreate all databases in '{}'. Continue?",
        container_name
    )) {
        println!("Aborted.");
        return;
    }

    // Decompress the backup
    println!("\nDecompressing backup...");
    let file = std::fs::File::open(&backup_path).expect("Failed to open backup file");
    let mut decoder = flate2::read::GzDecoder::new(file);
    let mut sql = Vec::new();
    decoder.read_to_end(&mut sql).expect("Failed to decompress backup");

    // Get postgres user from the container's env vars
    let inspect_output = Command::new("docker")
        .args(["inspect", "--format", "{{range .Config.Env}}{{println .}}{{end}}", &container_name])
        .output()
        .expect("Failed to inspect container");

    let env_str = String::from_utf8_lossy(&inspect_output.stdout);
    let mut user = "postgres".to_string();
    let mut password = String::new();
    for line in env_str.lines() {
        if let Some((key, value)) = line.split_once('=') {
            if key == "POSTGRES_USER" {
                user = value.to_string();
            } else if key == "POSTGRES_PASSWORD" {
                password = value.to_string();
            }
        }
    }

    // Find database names from \connect lines in the dump
    let sql_str = String::from_utf8_lossy(&sql);
    let skip = ["postgres", "template0", "template1"];
    let mut databases: BTreeSet<String> = BTreeSet::new();
    for line in sql_str.lines() {
        if let Some(rest) = line.strip_prefix("\\connect ") {
            let db_name = rest.split_whitespace().next().unwrap_or("");
            if !db_name.is_empty() && !skip.contains(&db_name) {
                databases.insert(db_name.to_string());
            }
        }
    }

    // Drop and recreate each database
    for db in &databases {
        println!("Dropping database '{}'...", db);
        let drop_sql = format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{db}';\nDROP DATABASE IF EXISTS \"{db}\";",
        );
        run_psql(&container_name, &user, &password, "postgres", drop_sql.as_bytes());
    }

    // Restore the full dump
    println!("Restoring from backup...");
    if run_psql(&container_name, &user, &password, "postgres", &sql) {
        println!("Restore complete.");
    } else {
        eprintln!("Restore completed with errors.");
        std::process::exit(1);
    }
}

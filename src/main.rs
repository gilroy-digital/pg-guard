use bollard::Docker;
use chrono::Utc;
use clap::Parser;
use std::path::{Path, PathBuf};
use tokio::process::Command;

async fn cleanup_old_backups(target: &Path, keep: usize) {
    let mut files = vec![];
    let mut dir = tokio::fs::read_dir(target).await.unwrap();
    while let Some(entry) = dir.next_entry().await.unwrap() {
        let path = entry.path();
        if path.is_file() {
            if let Some(filename) = path.file_name().and_then(|s| s.to_str()) {
                if filename.ends_with(".sql.gz") {
                    files.push((filename.to_string(), path));
                }
            }
        }
    }
    files.sort_by(|a, b| b.0.cmp(&a.0));
    for (_, path) in files.iter().skip(keep) {
        let _ = tokio::fs::remove_file(path).await;
    }
}

fn load_keep_runs(target: &Path) -> usize {
    let config_path = target.join(".pg_guard_config.json");
    if let Ok(s) = std::fs::read_to_string(config_path) {
        if let Ok(v) = serde_json::from_str::<serde_json::Value>(&s) {
            if let Some(k) = v.get("keep_runs").and_then(|v| v.as_u64()) {
                return k as usize;
            }
        }
    }
    std::env::var("PG_KEEP_RUNS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(14)
}

#[derive(Parser)]
struct Args {
    /// Target directory for backups
    target: PathBuf,

    /// Only backup a specific container
    #[arg(long)]
    container: Option<String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    // Create target directory if it doesn't exist
    tokio::fs::create_dir_all(&args.target).await?;

    let keep_runs = load_keep_runs(&args.target);

    let docker = Docker::connect_with_socket_defaults()?;

    // List all containers
    let containers = docker.list_containers::<String>(None).await?;
    let mut found = false;

    for container in containers {
        if let Some(image) = container.image {
            if image.contains("postgres") {
                if let Some(names) = container.names {
                    let name = names[0].trim_start_matches('/');

                    // Filter by container name if specified
                    if let Some(ref filter) = args.container {
                        if name != filter {
                            continue;
                        }
                    }

                    found = true;
                    println!("Backing up Postgres container: {}", name);

                    // Inspect container to get env vars
                    let inspect = docker.inspect_container(name, None).await?;
                    let env_vars = inspect.config.and_then(|c| c.env).unwrap_or_default();
                    let mut user = "postgres".to_string();
                    let mut password = std::env::var("PGPASSWORD").unwrap_or_default();
                    for env_var in env_vars {
                        if let Some((key, value)) = env_var.split_once('=') {
                            if key == "POSTGRES_USER" {
                                user = value.to_string();
                            } else if key == "POSTGRES_PASSWORD" {
                                password = value.to_string();
                            }
                        }
                    }

                    // Create container backup directory
                    let container_dir = args.target.join(name);
                    tokio::fs::create_dir_all(&container_dir).await?;

                    // Use timestamp so multiple backups per day are distinct
                    let timestamp = Utc::now().format("%Y-%m-%d_%H%M%S").to_string();
                    let output_file = container_dir.join(format!("{}.sql.gz", timestamp));
                    let temp_file = container_dir.join(format!("{}.sql", timestamp));
                    let cmd = format!("pg_dumpall --clean -U {}", user);
                    let output = Command::new("docker")
                        .arg("exec")
                        .arg("-e")
                        .arg(format!("PGPASSWORD={}", password))
                        .arg(name)
                        .arg("sh")
                        .arg("-c")
                        .arg(cmd)
                        .output()
                        .await?;

                    if output.status.success() {
                        tokio::fs::write(&temp_file, &output.stdout).await?;
                        let gzip_status = Command::new("gzip")
                            .arg("-f")
                            .arg(&temp_file)
                            .status()
                            .await?;
                        if gzip_status.success() {
                            println!("Backup saved to {:?}", output_file);
                            cleanup_old_backups(&container_dir, keep_runs).await;
                        } else {
                            eprintln!("Failed to gzip backup for {}", name);
                        }
                    } else {
                        eprintln!(
                            "Failed to backup {}: {:?}",
                            name,
                            String::from_utf8_lossy(&output.stderr)
                        );
                    }
                }
            }
        }
    }

    if !found {
        if let Some(ref filter) = args.container {
            eprintln!("No running Postgres container named '{}' found", filter);
        } else {
            eprintln!("No running Postgres containers found");
        }
    }

    Ok(())
}

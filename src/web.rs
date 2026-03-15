use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{Html, IntoResponse, Redirect},
    routing::{get, post},
    Json, Router,
};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::{SaltString, rand_core::OsRng}};
use axum_extra::extract::cookie::{Cookie, CookieJar};
use flate2::read::GzDecoder;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::{BufRead, BufReader, Read};
use std::process::Command;
use std::sync::Arc;
use tokio::sync::{watch, Mutex, RwLock};

// --- Config ---

#[derive(Clone, Debug, Serialize, Deserialize, Default)]
struct AuthConfig {
    username: String,
    /// Argon2id PHC-format hash (includes salt, params, and hash)
    password_phc: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Config {
    keep_runs: usize,
    schedule_hour: u8,
    schedule_minute: u8,
    interval_hours: u32,
    #[serde(default = "default_true")]
    backups_enabled: bool,
    #[serde(default)]
    auth: Option<AuthConfig>,
}

fn default_true() -> bool { true }

impl Default for Config {
    fn default() -> Self {
        Self {
            keep_runs: std::env::var("PG_KEEP_RUNS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(14),
            schedule_hour: 0,
            schedule_minute: 0,
            interval_hours: 24,
            backups_enabled: true,
            auth: None,
        }
    }
}

fn hash_password(password: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(password.as_bytes(), &salt)
        .expect("Failed to hash password")
        .to_string()
}

fn verify_password(password: &str, phc: &str) -> bool {
    let parsed = match PasswordHash::new(phc) {
        Ok(h) => h,
        Err(_) => return false,
    };
    Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok()
}

fn generate_session_token() -> String {
    use argon2::password_hash::rand_core::RngCore;
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn config_path(backup_dir: &str) -> std::path::PathBuf {
    std::path::Path::new(backup_dir).join(".pg_guard_config.json")
}

fn load_config(backup_dir: &str) -> Config {
    let path = config_path(backup_dir);
    match std::fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => Config::default(),
    }
}

fn save_config(backup_dir: &str, config: &Config) {
    let path = config_path(backup_dir);
    let json = serde_json::to_string_pretty(config).unwrap();
    let _ = std::fs::write(path, json);
}

// --- State ---

#[derive(Clone)]
struct AppState {
    backup_dir: String,
    busy: Arc<Mutex<()>>,
    config: Arc<RwLock<Config>>,
    schedule_notify: watch::Sender<()>,
    sessions: Arc<RwLock<HashSet<String>>>,
}

impl AppState {
    async fn is_authenticated(&self, jar: &CookieJar) -> bool {
        let config = self.config.read().await;
        if config.auth.is_none() {
            return false; // no auth configured, needs setup
        }
        if let Some(cookie) = jar.get("pg_guard_session") {
            self.sessions.read().await.contains(cookie.value())
        } else {
            false
        }
    }

    async fn needs_setup(&self) -> bool {
        self.config.read().await.auth.is_none()
    }
}

// --- Data types ---

#[derive(Serialize)]
struct ContainerInfo {
    name: String,
    backups: Vec<BackupInfo>,
}

#[derive(Serialize)]
struct BackupInfo {
    filename: String,
    size_display: String,
}

#[derive(Serialize)]
struct TableData {
    columns: Vec<String>,
    rows: Vec<Vec<String>>,
}

// --- Helpers ---

fn format_size(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    }
}

fn list_containers(backup_dir: &str) -> Vec<ContainerInfo> {
    let base = std::path::Path::new(backup_dir);
    if !base.exists() {
        return vec![];
    }
    let mut result = vec![];
    let mut dirs: Vec<_> = std::fs::read_dir(base)
        .into_iter()
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_dir())
        .collect();
    dirs.sort_by_key(|e| e.file_name());

    for dir in dirs {
        let name = dir.file_name().to_string_lossy().to_string();
        let mut backups: Vec<BackupInfo> = std::fs::read_dir(dir.path())
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
                let size = e.metadata().map(|m| m.len()).unwrap_or(0);
                BackupInfo {
                    filename: e.file_name().to_string_lossy().to_string(),
                    size_display: format_size(size),
                }
            })
            .collect();
        backups.sort_by(|a, b| b.filename.cmp(&a.filename));
        if !backups.is_empty() {
            result.push(ContainerInfo { name, backups });
        }
    }
    result
}

fn parse_backup_tables(
    backup_dir: &str,
    container: &str,
    filename: &str,
) -> BTreeMap<String, TableData> {
    let path = std::path::Path::new(backup_dir)
        .join(container)
        .join(filename);
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(_) => return BTreeMap::new(),
    };
    let decoder = GzDecoder::new(file);
    let reader = BufReader::new(decoder);

    let mut tables: BTreeMap<String, TableData> = BTreeMap::new();
    let mut current_table: Option<String> = None;

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
                let columns: Vec<String> =
                    cols_str.split(',').map(|c| c.trim().to_string()).collect();
                current_table = Some(table_name.clone());
                tables.entry(table_name).or_insert_with(|| TableData {
                    columns,
                    rows: Vec::new(),
                });
            }
        } else if line == "\\." {
            current_table = None;
        } else if let Some(ref table_name) = current_table {
            let values: Vec<String> = line.split('\t').map(|v| v.to_string()).collect();
            if let Some(table) = tables.get_mut(table_name) {
                table.rows.push(values);
            }
        }
    }

    tables
}

fn get_container_env(container: &str) -> (String, String) {
    let output = Command::new("docker")
        .args([
            "inspect",
            "--format",
            "{{range .Config.Env}}{{println .}}{{end}}",
            container,
        ])
        .output();

    let mut user = "postgres".to_string();
    let mut password = String::new();

    if let Ok(output) = output {
        let env_str = String::from_utf8_lossy(&output.stdout);
        for line in env_str.lines() {
            if let Some((key, value)) = line.split_once('=') {
                if key == "POSTGRES_USER" {
                    user = value.to_string();
                } else if key == "POSTGRES_PASSWORD" {
                    password = value.to_string();
                }
            }
        }
    }
    (user, password)
}

fn format_interval(hours: u32) -> String {
    match hours {
        1 => "Every hour".into(),
        h if h < 24 => format!("Every {} hours", h),
        24 => "Daily".into(),
        h if h % 24 == 0 => format!("Every {} days", h / 24),
        h => format!("Every {} hours", h),
    }
}

fn format_next_run(hour: u8, minute: u8, interval_hours: u32) -> String {
    let now = chrono::Utc::now();
    let today = now.date_naive();

    let target_time = chrono::NaiveTime::from_hms_opt(hour as u32, minute as u32, 0).unwrap();
    let mut next = today.and_time(target_time);

    // Find the next future run time
    let now_naive = now.naive_utc();
    while next <= now_naive {
        next += chrono::Duration::hours(interval_hours as i64);
    }

    let diff = next - now_naive;
    let hours = diff.num_hours();
    let mins = diff.num_minutes() % 60;

    if hours > 0 {
        format!("{}h {}m", hours, mins)
    } else {
        format!("{}m", mins)
    }
}

const PAGE_SIZE: usize = 100;

#[derive(Deserialize)]
struct PageParams {
    page: Option<usize>,
    q: Option<String>,
}

fn escape_html(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn urlencoded(s: &str) -> String {
    s.bytes().map(|b| match b {
        b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
            String::from(b as char)
        }
        _ => format!("%{:02X}", b),
    }).collect()
}

fn escape_attr(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('"', "&quot;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
}

fn render_data_table(
    title: &str,
    columns: &[String],
    rows: &[Vec<String>],
    total_rows: usize,
    page: usize,
    base_url: &str,
) -> String {
    render_data_table_with_search(title, columns, rows, total_rows, page, base_url, "", false)
}

fn render_data_table_with_search(
    title: &str,
    columns: &[String],
    rows: &[Vec<String>],
    total_rows: usize,
    page: usize,
    base_url: &str,
    search_query: &str,
    is_live: bool,
) -> String {
    let start = page * PAGE_SIZE;
    let showing_from = start + 1;
    let showing_to = (start + rows.len()).min(total_rows);
    let total_pages = (total_rows + PAGE_SIZE - 1) / PAGE_SIZE;

    // Encode columns as JSON for JS
    let cols_json: Vec<String> = columns.iter().map(|c| format!("\"{}\"", escape_attr(c))).collect();
    let cols_attr = format!("[{}]", cols_json.join(","));

    let mut header = String::from(r#"<th class="row-num">#</th>"#);
    for col in columns {
        header.push_str(&format!("<th>{}</th>", escape_html(col)));
    }

    let mut body = String::new();
    for (i, row) in rows.iter().enumerate() {
        // Encode row values as JSON array in data attribute
        let vals_json: Vec<String> = row.iter().map(|v| {
            let json_escaped = v
                .replace('\\', "\\\\")
                .replace('"', "\\\"")
                .replace('\n', "\\n")
                .replace('\r', "\\r")
                .replace('\t', "\\t");
            format!("\"{}\"", json_escaped)
        }).collect();
        let row_attr = format!("[{}]", vals_json.join(","));

        body.push_str(&format!(
            r#"<tr class="data-row" data-row-idx="{}" data-row-vals="{}" onclick="selectRow(this)">"#,
            start + i + 1,
            escape_attr(&row_attr)
        ));
        body.push_str(&format!(r#"<td class="row-num">{}</td>"#, start + i + 1));
        for val in row {
            if val == "\\N" || val.is_empty() {
                body.push_str(r#"<td class="cell-null">NULL</td>"#);
            } else if val == "t" || val == "true" {
                body.push_str(r#"<td style="color:var(--bool-true)">&#10003;</td>"#);
            } else if val == "f" || val == "false" {
                body.push_str(r#"<td style="color:var(--bool-false)">&#10007;</td>"#);
            } else {
                let display = if val.len() > 120 {
                    format!("{}...", &val[..117])
                } else {
                    val.clone()
                };
                body.push_str(&format!("<td title=\"{}\">{}</td>", escape_html(val), escape_html(&display)));
            }
        }
        body.push_str("</tr>");
    }

    let mut pagination = String::new();
    if total_pages > 1 {
        let prev_disabled = if page == 0 { " disabled style=\"opacity:0.4;pointer-events:none\"" } else { "" };
        let next_disabled = if page + 1 >= total_pages { " disabled style=\"opacity:0.4;pointer-events:none\"" } else { "" };
        let sep = if base_url.contains('?') { "&" } else { "?" };

        pagination = format!(
            r#"<div class="pagination">
                <a href="{base_url}{sep}page=0" class="btn btn-primary btn-sm"{prev_disabled}>First</a>
                <a href="{base_url}{sep}page={}" class="btn btn-primary btn-sm"{prev_disabled}>Prev</a>
                <span class="page-info">Page {} of {total_pages}</span>
                <a href="{base_url}{sep}page={}" class="btn btn-primary btn-sm"{next_disabled}>Next</a>
                <a href="{base_url}{sep}page={}" class="btn btn-primary btn-sm"{next_disabled}>Last</a>
                <span class="page-info" style="margin-left:auto">Rows {showing_from}-{showing_to} of {total_rows}</span>
            </div>"#,
            if page > 0 { page - 1 } else { 0 },
            page + 1,
            page + 1,
            total_pages - 1,
        );
    }

    // Strip query params from base_url for the search form action
    let form_action = base_url.split('?').next().unwrap_or(base_url);
    let escaped_query = escape_attr(search_query);

    let search_bar = if is_live {
        format!(
            r#"<div style="display:flex;gap:0.5rem;margin-bottom:0.5rem;align-items:center;max-width:700px">
                <input type="text" class="table-search" placeholder="Filter this page..." oninput="filterRows(this)" style="margin:0;flex:1">
                <span style="color:var(--text-dim);font-family:var(--font-mono);font-size:0.72rem;white-space:nowrap">or</span>
                <form method="GET" action="{form_action}" style="display:flex;gap:0.35rem;flex:1;margin:0">
                    <input type="text" name="q" class="table-search" placeholder="Search entire table..." value="{escaped_query}" style="margin:0;flex:1">
                    <button type="submit" class="btn btn-primary btn-sm">Go</button>
                    <a href="{form_action}" class="btn btn-ghost btn-sm">Clear</a>
                </form>
            </div>"#
        )
    } else {
        r#"<div style="max-width:350px;margin-bottom:0.5rem"><input type="text" class="table-search" placeholder="Filter this page..." oninput="filterRows(this)" style="margin:0"></div>"#.to_string()
    };

    format!(
        r#"<div class="card data-view-card" data-columns="{cols_escaped}">
            <div class="card-header">
                <span class="card-title">{title}</span>
                <span class="badge">{total_rows} rows</span>
            </div>
            {search_bar}
            <div class="data-split">
                <div class="data-split-table">
                    <div class="data-table-wrap">
                        <table>
                            <thead><tr>{header}</tr></thead>
                            <tbody>{body}</tbody>
                        </table>
                    </div>
                    {pagination}
                </div>
                <div class="detail-panel" id="detail-panel">
                    <div class="detail-empty">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:32px;height:32px;color:var(--text-dim);margin-bottom:0.5rem"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="3" y1="9" x2="21" y2="9"></line><line x1="9" y1="21" x2="9" y2="9"></line></svg>
                        <span>Click a row to inspect</span>
                    </div>
                    <div class="detail-content" id="detail-content" style="display:none">
                        <div class="detail-header">
                            <span class="detail-title" id="detail-title">Row</span>
                            <button class="btn btn-ghost btn-sm" onclick="closeDetail()">Close</button>
                        </div>
                        <div class="detail-fields" id="detail-fields"></div>
                    </div>
                </div>
            </div>
        </div>"#,
        cols_escaped = escape_attr(&cols_attr)
    )
}

// --- HTML ---

const STYLE: &str = r#"
<style>
    @import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Mono:wght@400;500;600&family=Inter:wght@400;500;600;700&display=swap');
    :root {
        --bg: #141518; --bg-surface: #1c1d22; --bg-surface-2: #18191e; --bg-hover: #26272e;
        --border: #2a2b33; --border-subtle: #222329;
        --text: #c8cad0; --text-heading: #e8eaef; --text-muted: #8a8d96; --text-faint: #606370; --text-dim: #3e404a;
        --accent: #e8b86d; --accent-hover: #f0c87d;
        --accent-2: #7ec9a0;
        --bool-true: #7ec9a0; --bool-false: #d98e8e;
        --btn-primary: #5c8abf; --btn-primary-hover: #4a78ad;
        --btn-success: #6aaa8a; --btn-success-hover: #5a9a7a;
        --btn-danger: #c47070; --btn-danger-hover: #b45e5e;
        --ok-bg: #1a2b24; --ok-text: #7ec9a0; --ok-border: #2d4a3a;
        --err-bg: #2b1a1a; --err-text: #d98e8e; --err-border: #4a2d2d;
        --badge-bg: #26272e; --badge-text: #8a8d96;
        --input-bg: #18191e; --input-border: #333540;
        --donate-grad: linear-gradient(135deg, #e8b86d 0%, #d4945a 100%);
        --donate-text: #141518;
        --shadow: 0 1px 4px rgba(0,0,0,0.4);
        --shadow-lg: 0 8px 24px rgba(0,0,0,0.5);
        --font-mono: 'IBM Plex Mono', 'SF Mono', Menlo, monospace;
        --focus-ring: rgba(232,184,109,0.2);
        color-scheme: dark;
    }
    [data-theme="light"] {
        --bg: #f2f0eb; --bg-surface: #faf9f6; --bg-surface-2: #f0eeea; --bg-hover: #e8e6e0;
        --border: #ddd9d0; --border-subtle: #e8e5de;
        --text: #3d3a34; --text-heading: #1a1814; --text-muted: #6b6760; --text-faint: #9e9a92; --text-dim: #ccc8c0;
        --accent: #b07830; --accent-hover: #96642a;
        --accent-2: #3a8a5c;
        --bool-true: #3a8a5c; --bool-false: #b84040;
        --btn-primary: #4a7498; --btn-primary-hover: #3d6488;
        --btn-success: #4a8a6a; --btn-success-hover: #3d7a5a;
        --btn-danger: #b85050; --btn-danger-hover: #a84040;
        --ok-bg: #eef6f0; --ok-text: #3a8a5c; --ok-border: #c0dece;
        --err-bg: #faf0f0; --err-text: #b84040; --err-border: #e8c4c4;
        --badge-bg: #e8e5de; --badge-text: #6b6760;
        --input-bg: #faf9f6; --input-border: #ccc8be;
        --donate-grad: linear-gradient(135deg, #b07830 0%, #96642a 100%);
        --donate-text: #faf9f6;
        --shadow: 0 1px 3px rgba(0,0,0,0.06);
        --shadow-lg: 0 8px 24px rgba(0,0,0,0.08);
        --focus-ring: rgba(176,120,48,0.15);
        color-scheme: light;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; transition: background 0.25s, color 0.25s; -webkit-font-smoothing: antialiased; font-size: 14px; }
    .container { max-width: 1200px; margin: 0 auto; }

    /* Header */
    .header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 1.75rem; padding-bottom: 1rem; border-bottom: 1px solid var(--border); }
    .logo { display: flex; align-items: baseline; gap: 0.1rem; }
    .logo-pg { font-family: var(--font-mono); font-size: 1.6rem; font-weight: 600; color: var(--accent); letter-spacing: -1px; }
    .logo-dash { font-family: var(--font-mono); font-size: 1.6rem; font-weight: 400; color: var(--text-dim); }
    .logo-guard { font-family: var(--font-mono); font-size: 1.6rem; font-weight: 500; color: var(--text-heading); letter-spacing: -0.5px; }
    .logo-by { font-size: 0.7rem; color: var(--text-faint); margin-left: 0.75rem; font-weight: 400; letter-spacing: 0.02em; }
    .logo-by a { color: var(--text-faint); text-decoration: none; border-bottom: 1px dashed var(--border); transition: all 0.15s; }
    .logo-by a:hover { color: var(--accent); border-color: var(--accent); text-decoration: none; }

    /* Theme toggle & header icons */
    .theme-toggle { background: var(--bg-surface); border: 1px solid var(--border); border-radius: 6px; padding: 0.35rem; cursor: pointer; display: flex; align-items: center; gap: 0.3rem; color: var(--text-faint); transition: all 0.15s; text-decoration: none; }
    .theme-toggle:hover { border-color: var(--accent); color: var(--accent); text-decoration: none; }
    .theme-toggle svg { width: 16px; height: 16px; }

    /* Layout */
    .grid { display: grid; grid-template-columns: 1fr 320px; gap: 1.25rem; align-items: start; }
    @media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }

    /* Cards */
    .card { background: var(--bg-surface); border-radius: 8px; padding: 1.25rem; margin-bottom: 0.75rem; border: 1px solid var(--border); box-shadow: var(--shadow); transition: all 0.2s; }
    .card-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; flex-wrap: wrap; gap: 0.5rem; }
    .card-title { font-family: var(--font-mono); font-size: 0.95rem; font-weight: 600; color: var(--text-heading); letter-spacing: -0.3px; }

    /* Tables */
    table { width: 100%; border-collapse: collapse; font-size: 0.82rem; font-variant-numeric: tabular-nums; }
    th { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid var(--border); color: var(--text-faint); font-family: var(--font-mono); font-weight: 500; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.06em; position: sticky; top: 0; background: var(--bg-surface); z-index: 1; }
    td { padding: 0.45rem 0.75rem; border-bottom: 1px solid var(--border-subtle); max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; transition: background 0.1s; font-family: var(--font-mono); font-size: 0.78rem; }
    tr:hover td { background: var(--bg-hover); }
    .data-table-wrap { overflow-x: auto; max-height: 70vh; overflow-y: auto; border: 1px solid var(--border); border-radius: 6px; }
    .data-table-wrap table { margin: 0; }
    .data-table-wrap th { background: var(--bg-surface-2); }
    .row-num { color: var(--text-dim); font-size: 0.7rem; text-align: right; padding-right: 0.5rem; user-select: none; width: 3rem; min-width: 3rem; }
    td.cell-null { color: var(--text-dim); font-style: italic; }
    .table-wrap { overflow-x: auto; }
    .data-row { cursor: pointer; }
    tr.inspecting td { background: var(--bg-hover); }
    .data-row.selected td { background: var(--bg-hover); border-left: 2px solid var(--accent); }
    .data-row.selected td:first-child { border-left: 2px solid var(--accent); }

    /* Split view */
    .data-split { display: flex; gap: 0; }
    .data-split-table { flex: 1; min-width: 0; }
    .detail-panel { width: 340px; min-width: 340px; border-left: 1px solid var(--border); margin-left: 1rem; padding-left: 1rem; max-height: 75vh; overflow-y: auto; }
    .detail-empty { display: flex; flex-direction: column; align-items: center; justify-content: center; height: 200px; color: var(--text-dim); font-family: var(--font-mono); font-size: 0.78rem; text-align: center; }
    .detail-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.75rem; padding-bottom: 0.5rem; border-bottom: 1px solid var(--border); }
    .detail-title { font-family: var(--font-mono); font-size: 0.82rem; font-weight: 600; color: var(--accent); }
    .detail-fields { }
    .detail-field { margin-bottom: 0.6rem; }
    .detail-field-key { font-family: var(--font-mono); font-size: 0.68rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-faint); margin-bottom: 0.15rem; }
    .detail-field-val { font-family: var(--font-mono); font-size: 0.8rem; color: var(--text-heading); word-break: break-all; white-space: pre-wrap; line-height: 1.5; padding: 0.3rem 0.5rem; background: var(--bg-surface-2); border-radius: 4px; border: 1px solid var(--border-subtle); max-height: 120px; overflow-y: auto; }
    .detail-field-val.val-null { color: var(--text-dim); font-style: italic; background: none; border: none; padding: 0.3rem 0; }
    .detail-field-val.val-bool-true { color: var(--bool-true); background: none; border: none; padding: 0.3rem 0; }
    .detail-field-val.val-bool-false { color: var(--bool-false); background: none; border: none; padding: 0.3rem 0; }
    @media (max-width: 900px) { .detail-panel { display: none; } }

    /* Pagination */
    .pagination { display: flex; align-items: center; gap: 0.5rem; margin-top: 0.75rem; flex-wrap: wrap; }
    .pagination .btn { min-width: 4.5rem; text-align: center; }
    .page-info { font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-faint); }

    /* Buttons */
    .btn { display: inline-flex; align-items: center; justify-content: center; padding: 0.4rem 0.85rem; border-radius: 5px; border: 1px solid transparent; cursor: pointer; font-family: var(--font-mono); font-size: 0.78rem; font-weight: 500; text-decoration: none; transition: all 0.15s; gap: 0.3rem; letter-spacing: 0.01em; }
    .btn:hover { text-decoration: none; }
    .btn:active { transform: scale(0.98); }
    .btn-primary { background: var(--btn-primary); color: #fff; border-color: var(--btn-primary); }
    .btn-primary:hover { background: var(--btn-primary-hover); border-color: var(--btn-primary-hover); }
    .btn-success { background: var(--btn-success); color: #fff; border-color: var(--btn-success); }
    .btn-success:hover { background: var(--btn-success-hover); border-color: var(--btn-success-hover); }
    .btn-danger { background: var(--btn-danger); color: #fff; border-color: var(--btn-danger); }
    .btn-danger:hover { background: var(--btn-danger-hover); border-color: var(--btn-danger-hover); }
    .btn-sm { padding: 0.25rem 0.55rem; font-size: 0.72rem; }
    .btn-block { display: flex; width: 100%; justify-content: center; }
    .btn-ghost { background: transparent; color: var(--text-muted); border: 1px solid var(--border); }
    .btn-ghost:hover { background: var(--bg-hover); color: var(--text); border-color: var(--text-dim); }

    /* Badges & Status */
    .badge { display: inline-flex; align-items: center; padding: 0.15rem 0.5rem; border-radius: 3px; font-family: var(--font-mono); font-size: 0.68rem; font-weight: 500; background: var(--badge-bg); color: var(--badge-text); letter-spacing: 0.02em; }
    .status { display: inline-flex; align-items: center; padding: 0.15rem 0.5rem; border-radius: 3px; font-family: var(--font-mono); font-size: 0.72rem; font-weight: 500; }
    .status-ok { background: var(--ok-bg); color: var(--ok-text); }
    .status-err { background: var(--err-bg); color: var(--err-text); }

    /* Actions */
    .actions { display: flex; gap: 0.4rem; align-items: center; flex-wrap: wrap; }

    /* Links */
    a { color: var(--accent); text-decoration: none; transition: color 0.15s; }
    a:hover { color: var(--accent-hover); text-decoration: underline; }

    /* Breadcrumb */
    .breadcrumb { margin-bottom: 1.25rem; font-family: var(--font-mono); font-size: 0.78rem; color: var(--text-faint); display: flex; align-items: center; gap: 0.3rem; }
    .breadcrumb a { color: var(--accent); font-weight: 500; }

    /* Toast */
    .toast { position: fixed; top: 1rem; right: 1rem; padding: 0.65rem 1.1rem; border-radius: 6px; font-family: var(--font-mono); font-size: 0.78rem; font-weight: 500; z-index: 100; display: none; box-shadow: var(--shadow-lg); }
    .toast-ok { background: var(--ok-bg); color: var(--ok-text); border: 1px solid var(--ok-border); }
    .toast-err { background: var(--err-bg); color: var(--err-text); border: 1px solid var(--err-border); }
    .spinner { display: inline-block; width: 12px; height: 12px; border: 2px solid var(--text-dim); border-top-color: var(--accent); border-radius: 50%; animation: spin 0.6s linear infinite; vertical-align: middle; }
    @keyframes spin { to { transform: rotate(360deg); } }

    /* Forms */
    .form-group { margin-bottom: 0.75rem; }
    .form-group label { display: block; font-family: var(--font-mono); font-size: 0.68rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.06em; color: var(--text-faint); margin-bottom: 0.3rem; }
    .form-row { display: flex; gap: 0.5rem; }
    .form-row .form-group { flex: 1; }
    select, input[type="number"] { width: 100%; padding: 0.4rem 0.55rem; border-radius: 4px; border: 1px solid var(--input-border); background: var(--input-bg); color: var(--text); font-family: var(--font-mono); font-size: 0.8rem; transition: border-color 0.15s; appearance: none; }
    select:focus, input[type="number"]:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--focus-ring); }
    .config-value { font-family: var(--font-mono); font-size: 0.82rem; color: var(--text-heading); padding: 0.2rem 0; font-weight: 500; }

    /* Donate */
    .donate-card { background: var(--bg-surface); border: 1px solid var(--border); }
    .donate-card p { font-size: 0.82rem; color: var(--text-muted); line-height: 1.6; margin-bottom: 0.75rem; }
    .donate-btn { display: flex; align-items: center; justify-content: center; width: 100%; padding: 0.6rem 1rem; border-radius: 6px; border: none; cursor: pointer; font-family: var(--font-mono); font-size: 0.85rem; font-weight: 600; text-align: center; text-decoration: none; background: var(--donate-grad); color: var(--donate-text); transition: all 0.15s; letter-spacing: 0.02em; }
    .donate-btn:hover { opacity: 0.9; text-decoration: none; }

    /* Divider */
    hr { border: none; border-top: 1px solid var(--border); margin: 0.75rem 0; }

    /* Table list search & collapse */
    .table-search { width: 100%; padding: 0.45rem 0.7rem; border-radius: 5px; border: 1px solid var(--input-border); background: var(--input-bg); color: var(--text); font-family: var(--font-mono); font-size: 0.8rem; margin-bottom: 0.75rem; transition: border-color 0.15s; }
    .table-search:focus { outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px var(--focus-ring); }
    .table-search::placeholder { color: var(--text-dim); }
    .schema-group { margin-bottom: 0.15rem; }
    .schema-header { display: flex; align-items: center; gap: 0.5rem; padding: 0.4rem 0.7rem; cursor: pointer; user-select: none; border-radius: 4px; transition: background 0.1s; font-family: var(--font-mono); font-size: 0.73rem; font-weight: 600; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.05em; }
    .schema-header:hover { background: var(--bg-hover); }
    .schema-chevron { width: 12px; height: 12px; transition: transform 0.15s; flex-shrink: 0; color: var(--text-dim); }
    .schema-group.collapsed .schema-chevron { transform: rotate(-90deg); }
    .schema-group.collapsed .schema-body { display: none; }
    .schema-count { font-weight: 400; color: var(--text-dim); font-size: 0.68rem; }
    .no-results { padding: 1.5rem; text-align: center; color: var(--text-faint); font-family: var(--font-mono); font-size: 0.8rem; display: none; }

    /* Help */
    .help-content { font-size: 0.85rem; line-height: 1.7; color: var(--text); }
    .help-content h3 { font-family: var(--font-mono); font-size: 0.8rem; font-weight: 600; color: var(--accent); margin: 1.25rem 0 0.5rem; text-transform: uppercase; letter-spacing: 0.05em; }
    .help-content h3:first-child { margin-top: 0; }
    .help-content p { margin-bottom: 0.6rem; color: var(--text-muted); }
    .help-content ul { margin: 0 0 0.75rem 1.25rem; color: var(--text-muted); }
    .help-content li { margin-bottom: 0.35rem; }
    .help-content code { font-family: var(--font-mono); background: var(--bg-surface-2); padding: 0.15rem 0.4rem; border-radius: 3px; font-size: 0.78rem; color: var(--accent); border: 1px solid var(--border); }
</style>
"#;

fn layout(title: &str, breadcrumb: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PG-Guard - {title}</title>
    {STYLE}
</head>
<body>
    <div class="container">
        <div class="header">
            <a href="/" class="logo" style="text-decoration:none">
                <span class="logo-pg">PG</span><span class="logo-dash">-</span><span class="logo-guard">Guard</span>
                <span class="logo-by">by <span style="border-bottom:1px dashed var(--border)">Gilroy.Digital</span></span>
            </a>
            <div class="actions">
            <a href="/help" class="theme-toggle" title="Instructions" aria-label="Instructions" style="font-family:var(--font-mono);font-size:0.72rem;padding:0.35rem 0.6rem">Instructions</a>
            <button class="theme-toggle" onclick="toggleTheme()" title="Toggle light/dark mode" aria-label="Toggle theme">
                <svg id="theme-icon-dark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 12.79A9 9 0 1 1 11.21 3a7 7 0 0 0 9.79 9.79z"></path></svg>
                <svg id="theme-icon-light" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="display:none"><circle cx="12" cy="12" r="5"></circle><line x1="12" y1="1" x2="12" y2="3"></line><line x1="12" y1="21" x2="12" y2="23"></line><line x1="4.22" y1="4.22" x2="5.64" y2="5.64"></line><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"></line><line x1="1" y1="12" x2="3" y2="12"></line><line x1="21" y1="12" x2="23" y2="12"></line><line x1="4.22" y1="19.78" x2="5.64" y2="18.36"></line><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"></line></svg>
            </button>
            <form method="POST" action="/logout" style="margin:0"><button type="submit" class="theme-toggle" title="Sign out" aria-label="Sign out"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"></path><polyline points="16 17 21 12 16 7"></polyline><line x1="21" y1="12" x2="9" y2="12"></line></svg></button></form>
            </div>
        </div>
        <div class="breadcrumb">{breadcrumb}</div>
        {body}
    </div>
    <div id="toast" class="toast"></div>
    <script>
    (function() {{
        const saved = localStorage.getItem('pg-guard-theme');
        const theme = saved || 'dark';
        document.documentElement.setAttribute('data-theme', theme);
        updateIcon(theme);
    }})();
    function updateIcon(theme) {{
        const d = document.getElementById('theme-icon-dark');
        const l = document.getElementById('theme-icon-light');
        if (d && l) {{ d.style.display = theme === 'dark' ? 'block' : 'none'; l.style.display = theme === 'light' ? 'block' : 'none'; }}
    }}
    function toggleTheme() {{
        const current = document.documentElement.getAttribute('data-theme');
        const next = current === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('pg-guard-theme', next);
        updateIcon(next);
    }}
    function showToast(msg, ok) {{
        const t = document.getElementById('toast');
        t.textContent = msg;
        t.className = 'toast ' + (ok ? 'toast-ok' : 'toast-err');
        t.style.display = 'block';
        setTimeout(() => t.style.display = 'none', 4000);
    }}
    async function doAction(url, method, btn, confirmMsg) {{
        if (confirmMsg && !confirm(confirmMsg)) return;
        const orig = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span> Working...';
        btn.disabled = true;
        try {{
            const res = await fetch(url, {{ method }});
            const data = await res.json();
            showToast(data.message, data.success);
            if (data.success && data.reload) setTimeout(() => location.reload(), 1000);
        }} catch(e) {{
            showToast('Request failed: ' + e, false);
        }}
        btn.innerHTML = orig;
        btn.disabled = false;
    }}
    async function saveConfig() {{
        const hour = document.getElementById('cfg-hour').value;
        const minute = document.getElementById('cfg-minute').value;
        const interval = document.getElementById('cfg-interval').value;
        const keep = document.getElementById('cfg-keep').value;
        const btn = document.getElementById('save-config-btn');
        const orig = btn.innerHTML;
        btn.innerHTML = '<span class="spinner"></span> Saving...';
        btn.disabled = true;
        try {{
            const res = await fetch('/api/config', {{
                method: 'POST',
                headers: {{ 'Content-Type': 'application/json' }},
                body: JSON.stringify({{ schedule_hour: parseInt(hour), schedule_minute: parseInt(minute), interval_hours: parseInt(interval), keep_runs: parseInt(keep), backups_enabled: document.getElementById('cfg-backups').checked }})
            }});
            const data = await res.json();
            showToast(data.message, data.success);
            if (data.success) setTimeout(() => location.reload(), 1000);
        }} catch(e) {{
            showToast('Request failed: ' + e, false);
        }}
        btn.innerHTML = orig;
        btn.disabled = false;
    }}
    function filterTables() {{
        const q = document.getElementById('table-search');
        const cq = document.getElementById('column-search');
        if (!q) return;
        const val = q.value.toLowerCase();
        const colVal = cq ? cq.value.toLowerCase() : '';
        const groups = document.querySelectorAll('.schema-group');
        const noRes = document.getElementById('no-results');
        let totalVisible = 0;
        groups.forEach(g => {{
            const rows = g.querySelectorAll('tbody tr');
            let visible = 0;
            rows.forEach(r => {{
                const name = r.getAttribute('data-name') || '';
                let nameMatch = name.includes(val);
                let colMatch = true;
                if (colVal) {{
                    const colsAttr = r.getAttribute('data-table-cols');
                    if (colsAttr) {{
                        try {{
                            const cols = JSON.parse(colsAttr);
                            colMatch = cols.some(c => c.name.toLowerCase().includes(colVal));
                        }} catch(e) {{ colMatch = false; }}
                    }} else {{ colMatch = false; }}
                }}
                const show = nameMatch && colMatch;
                r.style.display = show ? '' : 'none';
                if (show) visible++;
            }});
            g.style.display = visible > 0 ? '' : 'none';
            if (visible > 0 && val) g.classList.remove('collapsed');
            const cnt = g.querySelector('.schema-count');
            if (cnt) cnt.textContent = visible + ' tables';
            totalVisible += visible;
        }});
        if (noRes) noRes.style.display = totalVisible === 0 ? 'block' : 'none';
    }}
    function toggleSchema(el) {{
        el.closest('.schema-group').classList.toggle('collapsed');
    }}
    function inspectTable(btn) {{
        const tr = btn.closest('tr');
        const cols = JSON.parse(tr.getAttribute('data-table-cols') || '[]');
        const name = tr.querySelector('a') ? tr.querySelector('a').textContent : '';
        const panel = document.getElementById('inspect-panel');
        if (!panel) return;
        const content = document.getElementById('inspect-content');
        const empty = panel.querySelector('.detail-empty');
        const title = document.getElementById('inspect-title');
        const fields = document.getElementById('inspect-fields');
        // Highlight row
        document.querySelectorAll('tr.inspecting').forEach(r => r.classList.remove('inspecting'));
        tr.classList.add('inspecting');
        empty.style.display = 'none';
        content.style.display = 'block';
        title.textContent = name;
        fields.innerHTML = '';
        cols.forEach(col => {{
            const div = document.createElement('div');
            div.className = 'detail-field';
            const key = document.createElement('div');
            key.className = 'detail-field-key';
            key.textContent = col.name;
            const val = document.createElement('div');
            val.className = 'detail-field-val';
            let info = col.type;
            if (col.nullable === 'YES') info += '  \u00b7  nullable';
            else if (col.nullable === 'NO') info += '  \u00b7  not null';
            val.textContent = info;
            div.appendChild(key);
            div.appendChild(val);
            fields.appendChild(div);
        }});
    }}
    function closeInspect() {{
        document.querySelectorAll('tr.inspecting').forEach(r => r.classList.remove('inspecting'));
        const panel = document.getElementById('inspect-panel');
        if (!panel) return;
        panel.querySelector('.detail-empty').style.display = 'flex';
        document.getElementById('inspect-content').style.display = 'none';
    }}
    function filterByColumn() {{
        filterTables();
    }}
    function filterRows(input) {{
        const val = input.value.toLowerCase();
        const rows = document.querySelectorAll('.data-row');
        rows.forEach(r => {{
            const text = r.textContent.toLowerCase();
            r.style.display = text.includes(val) ? '' : 'none';
        }});
    }}
    function selectRow(tr) {{
        document.querySelectorAll('.data-row.selected').forEach(r => r.classList.remove('selected'));
        tr.classList.add('selected');
        const card = tr.closest('.data-view-card');
        if (!card) return;
        const cols = JSON.parse(card.getAttribute('data-columns') || '[]');
        const vals = JSON.parse(tr.getAttribute('data-row-vals') || '[]');
        const idx = tr.getAttribute('data-row-idx');
        const panel = document.getElementById('detail-panel');
        const content = document.getElementById('detail-content');
        const empty = panel.querySelector('.detail-empty');
        const title = document.getElementById('detail-title');
        const fields = document.getElementById('detail-fields');
        empty.style.display = 'none';
        content.style.display = 'block';
        title.textContent = 'Row #' + idx;
        fields.innerHTML = '';
        cols.forEach((col, i) => {{
            const val = i < vals.length ? vals[i] : '';
            const div = document.createElement('div');
            div.className = 'detail-field';
            const key = document.createElement('div');
            key.className = 'detail-field-key';
            key.textContent = col;
            const valDiv = document.createElement('div');
            valDiv.className = 'detail-field-val';
            if (val === '\\N' || val === '') {{
                valDiv.className += ' val-null';
                valDiv.textContent = 'NULL';
            }} else if (val === 't' || val === 'true') {{
                valDiv.className += ' val-bool-true';
                valDiv.textContent = '\u2713 true';
            }} else if (val === 'f' || val === 'false') {{
                valDiv.className += ' val-bool-false';
                valDiv.textContent = '\u2717 false';
            }} else {{
                valDiv.textContent = val;
            }}
            div.appendChild(key);
            div.appendChild(valDiv);
            fields.appendChild(div);
        }});
    }}
    function closeDetail() {{
        document.querySelectorAll('.data-row.selected').forEach(r => r.classList.remove('selected'));
        const panel = document.getElementById('detail-panel');
        if (!panel) return;
        panel.querySelector('.detail-empty').style.display = 'flex';
        document.getElementById('detail-content').style.display = 'none';
    }}
    function toggleAll(expand) {{
        document.querySelectorAll('.schema-group').forEach(g => {{
            if (expand) g.classList.remove('collapsed');
            else g.classList.add('collapsed');
        }});
    }}
    function filterContainers() {{
        const q = document.getElementById('container-search');
        if (!q) return;
        const val = q.value.toLowerCase();
        const cards = document.querySelectorAll('.container-card');
        const noRes = document.getElementById('no-container-results');
        let visible = 0;
        cards.forEach(c => {{
            const name = c.getAttribute('data-name') || '';
            const show = name.includes(val);
            c.style.display = show ? '' : 'none';
            if (show) visible++;
        }});
        if (noRes) noRes.style.display = visible === 0 ? 'block' : 'none';
    }}
    </script>
</body>
</html>"#
    )
}

// --- Auth pages ---

fn auth_page(title: &str, body: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en" data-theme="dark">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PG-Guard - {title}</title>
    {STYLE}
    <style>
        .auth-wrap {{ display: flex; justify-content: center; align-items: center; min-height: 80vh; }}
        .auth-card {{ width: 100%; max-width: 400px; }}
        .auth-card .logo {{ justify-content: center; margin-bottom: 2rem; }}
        .auth-field {{ margin-bottom: 1rem; }}
        .auth-field label {{ display: block; font-size: 0.8rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.04em; color: var(--text-muted); margin-bottom: 0.35rem; }}
        .auth-field input {{ width: 100%; padding: 0.6rem 0.75rem; border-radius: 7px; border: 1px solid var(--input-border); background: var(--input-bg); color: var(--text); font-size: 0.9rem; }}
        .auth-field input:focus {{ outline: none; border-color: var(--accent); box-shadow: 0 0 0 3px rgba(56,189,248,0.15); }}
        .auth-submit {{ width: 100%; padding: 0.65rem; border-radius: 7px; border: none; cursor: pointer; font-size: 0.9rem; font-weight: 600; background: var(--btn-primary); color: white; margin-top: 0.5rem; }}
        .auth-submit:hover {{ background: var(--btn-primary-hover); }}
        .auth-error {{ background: var(--err-bg); color: var(--err-text); border: 1px solid var(--err-border); padding: 0.5rem 0.75rem; border-radius: 6px; font-size: 0.85rem; margin-bottom: 1rem; }}
        .auth-subtitle {{ color: var(--text-muted); font-size: 0.85rem; text-align: center; margin-bottom: 1.5rem; }}
    </style>
    <script>
    (function() {{
        const saved = localStorage.getItem('pg-guard-theme');
        document.documentElement.setAttribute('data-theme', saved || 'dark');
    }})();
    </script>
</head>
<body>
    <div class="container">
        <div class="auth-wrap">
            <div class="auth-card">
                <div class="logo" style="justify-content:center">
                    <span class="logo-pg">PG</span><span class="logo-dash">-</span><span class="logo-guard">Guard</span>
                </div>
                {body}
            </div>
        </div>
    </div>
</body>
</html>"#
    )
}

#[derive(Deserialize)]
struct SetupForm {
    username: String,
    password: String,
    password_confirm: String,
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn setup_page(State(state): State<AppState>) -> impl IntoResponse {
    if !state.needs_setup().await {
        return Redirect::to("/login").into_response();
    }
    Html(auth_page("Setup", r#"
        <p class="auth-subtitle">Create your admin account to get started</p>
        <form method="POST" action="/setup">
            <div class="auth-field">
                <label>Username</label>
                <input type="text" name="username" required autofocus>
            </div>
            <div class="auth-field">
                <label>Password</label>
                <input type="password" name="password" required minlength="6">
            </div>
            <div class="auth-field">
                <label>Confirm Password</label>
                <input type="password" name="password_confirm" required minlength="6">
            </div>
            <button type="submit" class="auth-submit">Create Account</button>
        </form>
    "#)).into_response()
}

async fn setup_submit(
    State(state): State<AppState>,
    axum::Form(form): axum::Form<SetupForm>,
) -> impl IntoResponse {
    if !state.needs_setup().await {
        return Redirect::to("/login").into_response();
    }

    if form.password != form.password_confirm {
        return Html(auth_page("Setup", r#"
            <div class="auth-error">Passwords do not match</div>
            <form method="POST" action="/setup">
                <div class="auth-field">
                    <label>Username</label>
                    <input type="text" name="username" required autofocus>
                </div>
                <div class="auth-field">
                    <label>Password</label>
                    <input type="password" name="password" required minlength="6">
                </div>
                <div class="auth-field">
                    <label>Confirm Password</label>
                    <input type="password" name="password_confirm" required minlength="6">
                </div>
                <button type="submit" class="auth-submit">Create Account</button>
            </form>
        "#)).into_response();
    }

    if form.username.trim().is_empty() || form.password.len() < 6 {
        return Html(auth_page("Setup", r#"
            <div class="auth-error">Username required and password must be at least 6 characters</div>
            <form method="POST" action="/setup">
                <div class="auth-field">
                    <label>Username</label>
                    <input type="text" name="username" required autofocus>
                </div>
                <div class="auth-field">
                    <label>Password</label>
                    <input type="password" name="password" required minlength="6">
                </div>
                <div class="auth-field">
                    <label>Confirm Password</label>
                    <input type="password" name="password_confirm" required minlength="6">
                </div>
                <button type="submit" class="auth-submit">Create Account</button>
            </form>
        "#)).into_response();
    }

    let password_phc = hash_password(&form.password);

    {
        let mut config = state.config.write().await;
        config.auth = Some(AuthConfig {
            username: form.username.trim().to_string(),
            password_phc,
        });
        save_config(&state.backup_dir, &config);
    }

    // Auto-login after setup
    let token = generate_session_token();
    state.sessions.write().await.insert(token.clone());

    let cookie = Cookie::build(("pg_guard_session", token))
        .path("/")
        .http_only(true)
        .same_site(axum_extra::extract::cookie::SameSite::Lax)
        .build();

    (CookieJar::new().add(cookie), Redirect::to("/")).into_response()
}

async fn login_page(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    if state.needs_setup().await {
        return Redirect::to("/setup").into_response();
    }
    if state.is_authenticated(&jar).await {
        return Redirect::to("/").into_response();
    }
    Html(auth_page("Login", r#"
        <p class="auth-subtitle">Sign in to your PG-Guard dashboard</p>
        <form method="POST" action="/login">
            <div class="auth-field">
                <label>Username</label>
                <input type="text" name="username" required autofocus>
            </div>
            <div class="auth-field">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="auth-submit">Sign In</button>
        </form>
    "#)).into_response()
}

async fn login_submit(
    State(state): State<AppState>,
    axum::Form(form): axum::Form<LoginForm>,
) -> impl IntoResponse {
    let config = state.config.read().await.clone();
    if let Some(auth) = &config.auth {
        if form.username == auth.username && verify_password(&form.password, &auth.password_phc) {
            let token = generate_session_token();
            state.sessions.write().await.insert(token.clone());

            let cookie = Cookie::build(("pg_guard_session", token))
                .path("/")
                .http_only(true)
                .same_site(axum_extra::extract::cookie::SameSite::Lax)
                .build();

            return (CookieJar::new().add(cookie), Redirect::to("/")).into_response();
        }
    }

    Html(auth_page("Login", r#"
        <div class="auth-error">Invalid username or password</div>
        <form method="POST" action="/login">
            <div class="auth-field">
                <label>Username</label>
                <input type="text" name="username" required autofocus>
            </div>
            <div class="auth-field">
                <label>Password</label>
                <input type="password" name="password" required>
            </div>
            <button type="submit" class="auth-submit">Sign In</button>
        </form>
    "#)).into_response()
}

async fn logout(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    if let Some(cookie) = jar.get("pg_guard_session") {
        state.sessions.write().await.remove(cookie.value());
    }
    let removal = Cookie::build(("pg_guard_session", ""))
        .path("/")
        .removal()
        .build();
    (CookieJar::new().add(removal), Redirect::to("/login"))
}

// Auth guard helper - returns redirect response if not authenticated
async fn require_auth(state: &AppState, jar: &CookieJar) -> Option<axum::response::Response> {
    if state.needs_setup().await {
        return Some(Redirect::to("/setup").into_response());
    }
    if !state.is_authenticated(jar).await {
        return Some(Redirect::to("/login").into_response());
    }
    None
}

// --- Routes ---

async fn dashboard(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    if let Some(r) = require_auth(&state, &jar).await { return r.into_response(); }
    let containers = list_containers(&state.backup_dir);
    let config = state.config.read().await.clone();

    let next_run = if config.backups_enabled {
        format!("Next run in {}", format_next_run(config.schedule_hour, config.schedule_minute, config.interval_hours))
    } else {
        "Backups disabled".to_string()
    };

    // Build hour options
    let mut hour_opts = String::new();
    for h in 0..24u8 {
        let sel = if h == config.schedule_hour { " selected" } else { "" };
        hour_opts.push_str(&format!(r#"<option value="{h}"{sel}>{h:02}</option>"#));
    }

    // Build minute options
    let mut minute_opts = String::new();
    for m in (0..60u8).step_by(5) {
        let sel = if m == config.schedule_minute { " selected" } else { "" };
        minute_opts.push_str(&format!(r#"<option value="{m}"{sel}>{m:02}</option>"#));
    }

    // Build interval options
    let intervals = [(1, "Every hour"), (2, "Every 2 hours"), (4, "Every 4 hours"), (6, "Every 6 hours"), (8, "Every 8 hours"), (12, "Every 12 hours"), (24, "Daily"), (48, "Every 2 days"), (168, "Weekly")];
    let mut interval_opts = String::new();
    for (val, label) in intervals {
        let sel = if val == config.interval_hours { " selected" } else { "" };
        interval_opts.push_str(&format!(r#"<option value="{val}"{sel}>{label}</option>"#));
    }

    // Build keep options
    let mut keep_opts = String::new();
    for k in [3, 5, 7, 14, 21, 30, 60, 90] {
        let sel = if k == config.keep_runs { " selected" } else { "" };
        keep_opts.push_str(&format!(r#"<option value="{k}"{sel}>{k} backups</option>"#));
    }

    // Sidebar
    let sidebar = format!(
        r#"
        <div class="card">
            <div class="card-header">
                <span class="card-title">Configuration</span>
            </div>
            <div class="form-group">
                <label>Schedule</label>
                <div class="config-value">{} starting at {:02}:{:02} UTC</div>
                <div class="config-value" style="font-size:0.8rem; color:var(--text-faint)">{next_run}</div>
            </div>
            <div class="form-group">
                <label>Retention</label>
                <div class="config-value">Keep {} backups per container</div>
            </div>
            <hr>
            <div class="form-row">
                <div class="form-group">
                    <label>Start hour</label>
                    <select id="cfg-hour">{hour_opts}</select>
                </div>
                <div class="form-group">
                    <label>Minute</label>
                    <select id="cfg-minute">{minute_opts}</select>
                </div>
            </div>
            <div class="form-group">
                <label>Frequency</label>
                <select id="cfg-interval">{interval_opts}</select>
            </div>
            <div class="form-group">
                <label>Retention</label>
                <select id="cfg-keep">{keep_opts}</select>
            </div>
            <div class="form-group">
                <label>Automatic Backups</label>
                <label style="display:flex;align-items:center;gap:0.5rem;cursor:pointer;text-transform:none;letter-spacing:0;font-weight:500;font-size:0.82rem;color:var(--text)">
                    <input type="checkbox" id="cfg-backups" {backups_checked} style="width:auto;accent-color:var(--accent)">
                    Enabled
                </label>
            </div>
            <button id="save-config-btn" class="btn btn-primary btn-block" onclick="saveConfig()">Save Settings</button>
        </div>

        <div class="card donate-card">
            <div class="card-header">
                <span class="card-title">Support pg_guard</span>
            </div>
            <p>pg_guard is free, open source software built and maintained by an independent developer. If it's saving you time or keeping your data safe, consider supporting its continued development.</p>
            <a href="https://donate.stripe.com/fZu6oHbg026l7EIax2fbq04" target="_blank" rel="noopener" class="donate-btn">Donate</a>
            <p style="margin-top:0.75rem; font-size:0.8rem; text-align:center; color:#64748b">&mdash; Leon | <a href="https://gilroy.digital/tools" target="_blank" rel="noopener">More tools</a></p>
        </div>
        "#,
        format_interval(config.interval_hours),
        config.schedule_hour,
        config.schedule_minute,
        config.keep_runs,
        backups_checked = if config.backups_enabled { "checked" } else { "" },
    );

    // Container cards
    let mut cards = String::new();

    // Top bar with search and backup all
    cards.push_str(
        r#"<div style="display:flex; gap:0.5rem; margin-bottom:1rem; align-items:center">
            <input type="text" id="container-search" class="table-search" placeholder="Search containers..." oninput="filterContainers()" style="margin-bottom:0; flex:1">
            <button class="btn btn-ghost btn-sm" onclick="toggleAll(false)" style="white-space:nowrap">Collapse All</button>
            <button class="btn btn-ghost btn-sm" onclick="toggleAll(true)" style="white-space:nowrap">Expand All</button>
            <button class="btn btn-success" onclick="doAction('/api/backup', 'POST', this)" style="white-space:nowrap">Backup All Now</button>
        </div>"#,
    );

    for c in &containers {
        let latest = c.backups.first();
        let latest_info = match latest {
            Some(b) => format!(
                r#"<span class="status status-ok">Latest: {}</span> <span class="badge">{}</span>"#,
                b.filename, b.size_display
            ),
            None => r#"<span class="status status-err">No backups</span>"#.to_string(),
        };

        let mut backup_rows = String::new();
        for b in &c.backups {
            backup_rows.push_str(&format!(
                r#"<tr>
                    <td>{}</td>
                    <td>{}</td>
                    <td class="actions">
                        <a href="/browse/{}/{}" class="btn btn-primary btn-sm">Browse</a>
                        <button class="btn btn-danger btn-sm" onclick="doAction('/api/restore/{}/{}', 'POST', this, 'DROP and restore all databases from this backup?')">Restore</button>
                    </td>
                </tr>"#,
                b.filename, b.size_display, c.name, b.filename, c.name, b.filename
            ));
        }

        cards.push_str(&format!(
            r#"<div class="container-card schema-group collapsed" data-name="{cname_lower}">
                <div class="card">
                    <div class="card-header" style="cursor:pointer" onclick="toggleSchema(this)">
                        <div class="actions" style="gap:0.4rem">
                            <svg class="schema-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
                            <span class="card-title">{cname}</span>
                            <span class="badge">{count} backups</span>
                        </div>
                        <div class="actions" onclick="event.stopPropagation()">
                            {latest_info}
                            <a href="/live/{cname}" class="btn btn-primary btn-sm">Live</a>
                            <button class="btn btn-success btn-sm" onclick="doAction('/api/backup/{cname}', 'POST', this)">Backup</button>
                        </div>
                    </div>
                    <div class="schema-body">
                        <table>
                            <thead><tr><th>Backup</th><th>Size</th><th>Actions</th></tr></thead>
                            <tbody>{backup_rows}</tbody>
                        </table>
                    </div>
                </div>
            </div>"#,
            cname = c.name,
            cname_lower = c.name.to_lowercase(),
            count = c.backups.len(),
        ));
    }

    if containers.is_empty() {
        cards.push_str(
            r#"<div class="card"><p>No backups found. Click "Backup All Now" to create your first backup.</p></div>"#,
        );
    }

    cards.push_str(r#"<div id="no-container-results" class="no-results">No containers match your search</div>"#);

    let body = format!(
        r#"<div class="grid"><div>{cards}</div><div>{sidebar}</div></div>"#
    );

    Html(layout("Dashboard", "Dashboard", &body)).into_response()
}

async fn browse_tables(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((container, filename)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Some(r) = require_auth(&state, &jar).await { return r.into_response(); }
    let tables = parse_backup_tables(&state.backup_dir, &container, &filename);

    // Group tables by schema prefix
    let mut schemas: BTreeMap<String, Vec<(&String, &TableData)>> = BTreeMap::new();
    for (name, data) in &tables {
        let schema = if let Some(dot) = name.find('.') {
            name[..dot].to_string()
        } else {
            "public".to_string()
        };
        schemas.entry(schema).or_default().push((name, data));
    }

    let mut groups = String::new();
    for (schema, items) in &schemas {
        let mut rows = String::new();
        for (name, data) in items {
            let display = if let Some(dot) = name.find('.') { &name[dot+1..] } else { name.as_str() };

            // Encode column names as JSON for inspect
            let col_info: Vec<String> = data.columns.iter().map(|c| {
                format!("{{\"name\":\"{}\",\"type\":\"—\",\"nullable\":\"—\"}}", escape_attr(c))
            }).collect();
            let col_attr = format!("[{}]", col_info.join(","));

            rows.push_str(&format!(
                r#"<tr data-name="{ln}" data-table-cols="{ca}">
                    <td style="white-space:nowrap"><a href="/browse/{container}/{filename}/{name}" class="btn btn-success btn-sm" title="Open table">Open</a> <button class="btn btn-ghost btn-sm" onclick="inspectTable(this)" title="Inspect columns">Inspect</button></td>
                    <td><a href="/browse/{container}/{filename}/{name}">{display}</a></td>
                    <td>{cols}</td>
                    <td>{rws}</td>
                </tr>"#,
                ln = name.to_lowercase(),
                ca = escape_attr(&col_attr),
                cols = data.columns.len(),
                rws = data.rows.len()
            ));
        }
        groups.push_str(&format!(
            r#"<div class="schema-group">
                <div class="schema-header" onclick="toggleSchema(this)">
                    <svg class="schema-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
                    {schema} <span class="schema-count">{} tables</span>
                </div>
                <div class="schema-body">
                    <table><thead><tr><th style="width:130px"></th><th>Table</th><th>Columns</th><th>Rows</th></tr></thead><tbody>{rows}</tbody></table>
                </div>
            </div>"#,
            items.len()
        ));
    }

    let body = format!(
        r#"<div class="card">
            <div class="card-header">
                <span class="card-title">Tables</span>
                <span class="badge">{} tables</span>
            </div>
            <div style="display:flex;gap:0.5rem;margin-bottom:0.5rem">
                <input type="text" id="table-search" class="table-search" placeholder="Search tables..." oninput="filterTables()" autofocus style="margin:0">
                <input type="text" id="column-search" class="table-search" placeholder="Search by column name..." oninput="filterByColumn()" style="margin:0">
            </div>
            <div class="data-split">
                <div class="data-split-table">
                    {groups}
                    <div id="no-results" class="no-results">No tables match your search</div>
                </div>
                <div class="detail-panel" id="inspect-panel">
                    <div class="detail-empty">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:32px;height:32px;color:var(--text-dim);margin-bottom:0.5rem"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="3" y1="9" x2="21" y2="9"></line><line x1="9" y1="21" x2="9" y2="9"></line></svg>
                        <span>Click Inspect to view columns</span>
                    </div>
                    <div class="detail-content" id="inspect-content" style="display:none">
                        <div class="detail-header">
                            <span class="detail-title" id="inspect-title">Table</span>
                            <button class="btn btn-ghost btn-sm" onclick="closeInspect()">Close</button>
                        </div>
                        <div class="detail-fields" id="inspect-fields"></div>
                    </div>
                </div>
            </div>
        </div>"#,
        tables.len()
    );

    let bc = format!(
        r#"<a href="/">Dashboard</a> / {} / {}"#,
        container, filename
    );
    Html(layout("Browse", &bc, &body)).into_response()
}

async fn browse_table_data(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((container, filename, table_name)): Path<(String, String, String)>,
    Query(params): Query<PageParams>,
) -> impl IntoResponse {
    if let Some(r) = require_auth(&state, &jar).await { return r.into_response(); }
    let tables = parse_backup_tables(&state.backup_dir, &container, &filename);
    let page = params.page.unwrap_or(0);

    let body = match tables.get(&table_name) {
        Some(data) => {
            let total = data.rows.len();
            let start = page * PAGE_SIZE;
            let page_rows: Vec<Vec<String>> = data.rows.iter().skip(start).take(PAGE_SIZE).cloned().collect();
            let base_url = format!("/browse/{}/{}/{}", container, filename, table_name);
            render_data_table(&table_name, &data.columns, &page_rows, total, page, &base_url)
        }
        None => r#"<div class="card"><p>Table not found.</p></div>"#.to_string(),
    };

    let bc = format!(
        r#"<a href="/">Dashboard</a> / <a href="/browse/{container}/{filename}">{container}/{filename}</a> / {table_name}"#,
    );
    Html(layout("Table", &bc, &body)).into_response()
}

// --- Live DB browsing ---

fn run_psql_query(container: &str, user: &str, password: &str, db: &str, query: &str) -> Option<String> {
    let output = Command::new("docker")
        .args(["exec", "-e"])
        .arg(format!("PGPASSWORD={}", password))
        .arg(container)
        .args(["psql", "-U", user, "-d", db, "-t", "-A", "-F", "\t", "-c", query])
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).to_string())
    } else {
        None
    }
}

async fn live_databases(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(container): Path<String>,
) -> impl IntoResponse {
    if let Some(r) = require_auth(&state, &jar).await { return r.into_response(); }
    let (user, password) = get_container_env(&container);

    let dbs = run_psql_query(
        &container, &user, &password, "postgres",
        "SELECT datname FROM pg_database WHERE datistemplate = false AND datname != 'postgres' ORDER BY datname",
    ).unwrap_or_default();

    let mut rows = String::new();
    for db in dbs.lines() {
        let db = db.trim();
        if db.is_empty() { continue; }
        let escaped = db.replace('&', "&amp;").replace('<', "&lt;").replace('>', "&gt;");
        rows.push_str(&format!(
            r#"<tr><td><a href="/live/{container}/{db}">{escaped}</a></td></tr>"#
        ));
    }

    let body = format!(
        r#"<div class="card">
            <div class="card-header">
                <span class="card-title">{container} - Live Databases</span>
            </div>
            <table>
                <thead><tr><th>Database</th></tr></thead>
                <tbody>{rows}</tbody>
            </table>
        </div>"#
    );

    let bc = format!(r#"<a href="/">Dashboard</a> / Live / {container}"#);
    Html(layout("Live", &bc, &body)).into_response()
}

async fn live_tables(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((container, db)): Path<(String, String)>,
) -> impl IntoResponse {
    if let Some(r) = require_auth(&state, &jar).await { return r.into_response(); }
    let (user, password) = get_container_env(&container);

    let tables_output = run_psql_query(
        &container, &user, &password, &db,
        "SELECT schemaname || '.' || tablename, pg_size_pretty(pg_total_relation_size(quote_ident(schemaname) || '.' || quote_ident(tablename))), (SELECT count(*) FROM information_schema.columns c WHERE c.table_schema = t.schemaname AND c.table_name = t.tablename), (SELECT n_live_tup FROM pg_stat_user_tables s WHERE s.schemaname = t.schemaname AND s.relname = t.tablename) FROM pg_tables t WHERE schemaname NOT IN ('pg_catalog', 'information_schema') ORDER BY schemaname, tablename",
    ).unwrap_or_default();

    // Get column info for all tables for the inspect panel
    let cols_output = run_psql_query(
        &container, &user, &password, &db,
        "SELECT table_schema || '.' || table_name, column_name, data_type, is_nullable FROM information_schema.columns WHERE table_schema NOT IN ('pg_catalog', 'information_schema') ORDER BY table_schema, table_name, ordinal_position",
    ).unwrap_or_default();

    // Build a map of table -> columns for inspect
    let mut table_columns: BTreeMap<String, Vec<(String, String, String)>> = BTreeMap::new();
    for line in cols_output.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        let parts: Vec<&str> = line.split('\t').collect();
        if parts.len() >= 4 {
            table_columns.entry(parts[0].to_string()).or_default().push(
                (parts[1].to_string(), parts[2].to_string(), parts[3].to_string())
            );
        }
    }

    // Parse and group by schema
    let mut schemas: BTreeMap<String, Vec<(String, String, String, String)>> = BTreeMap::new();
    let mut table_count = 0;
    for line in tables_output.lines() {
        let line = line.trim();
        if line.is_empty() { continue; }
        table_count += 1;
        let parts: Vec<&str> = line.split('\t').collect();
        let full_name = parts.first().unwrap_or(&"").to_string();
        let size = parts.get(1).unwrap_or(&"").to_string();
        let cols = parts.get(2).unwrap_or(&"").to_string();
        let est_rows = parts.get(3).unwrap_or(&"").to_string();
        let schema = if let Some(dot) = full_name.find('.') {
            full_name[..dot].to_string()
        } else {
            "public".to_string()
        };
        schemas.entry(schema).or_default().push((full_name, cols, est_rows, size));
    }

    let mut groups = String::new();
    for (schema, items) in &schemas {
        let mut rows = String::new();
        for (full_name, cols, est_rows, size) in items {
            let display = if let Some(dot) = full_name.find('.') { &full_name[dot+1..] } else { full_name.as_str() };
            let escaped = escape_html(display);

            // Encode column info as JSON for inspect
            let col_info = table_columns.get(full_name).map(|cols| {
                let entries: Vec<String> = cols.iter().map(|(name, dtype, nullable)| {
                    format!("{{\"name\":\"{}\",\"type\":\"{}\",\"nullable\":\"{}\"}}", escape_attr(name), escape_attr(dtype), nullable)
                }).collect();
                format!("[{}]", entries.join(","))
            }).unwrap_or_else(|| "[]".to_string());

            rows.push_str(&format!(
                r#"<tr data-name="{ln}" data-table-cols="{col_attr}">
                    <td style="white-space:nowrap"><a href="/live/{container}/{db}/{full_name}" class="btn btn-success btn-sm" title="Open table">Open</a> <button class="btn btn-ghost btn-sm" onclick="inspectTable(this)" title="Inspect columns">Inspect</button></td>
                    <td><a href="/live/{container}/{db}/{full_name}">{escaped}</a></td>
                    <td>{cols}</td>
                    <td>{est_rows}</td>
                    <td>{size}</td>
                </tr>"#,
                ln = full_name.to_lowercase(),
                col_attr = escape_attr(&col_info),
            ));
        }
        groups.push_str(&format!(
            r#"<div class="schema-group">
                <div class="schema-header" onclick="toggleSchema(this)">
                    <svg class="schema-chevron" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg>
                    {schema} <span class="schema-count">{} tables</span>
                </div>
                <div class="schema-body">
                    <table><thead><tr><th style="width:130px"></th><th>Table</th><th>Columns</th><th>Rows (est.)</th><th>Size</th></tr></thead><tbody>{rows}</tbody></table>
                </div>
            </div>"#,
            items.len()
        ));
    }

    let body = format!(
        r#"<div class="card">
            <div class="card-header">
                <span class="card-title">{db}</span>
                <div class="actions">
                    <span class="badge">{table_count} tables</span>
                    <span class="badge">live</span>
                </div>
            </div>
            <div style="display:flex;gap:0.5rem;margin-bottom:0.5rem">
                <input type="text" id="table-search" class="table-search" placeholder="Search tables..." oninput="filterTables()" autofocus style="margin:0">
                <input type="text" id="column-search" class="table-search" placeholder="Search by column name..." oninput="filterByColumn()" style="margin:0">
            </div>
            <div class="data-split">
                <div class="data-split-table">
                    {groups}
                    <div id="no-results" class="no-results">No tables match your search</div>
                </div>
                <div class="detail-panel" id="inspect-panel">
                    <div class="detail-empty">
                        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" style="width:32px;height:32px;color:var(--text-dim);margin-bottom:0.5rem"><rect x="3" y="3" width="18" height="18" rx="2" ry="2"></rect><line x1="3" y1="9" x2="21" y2="9"></line><line x1="9" y1="21" x2="9" y2="9"></line></svg>
                        <span>Click Inspect to view columns</span>
                    </div>
                    <div class="detail-content" id="inspect-content" style="display:none">
                        <div class="detail-header">
                            <span class="detail-title" id="inspect-title">Table</span>
                            <button class="btn btn-ghost btn-sm" onclick="closeInspect()">Close</button>
                        </div>
                        <div class="detail-fields" id="inspect-fields"></div>
                    </div>
                </div>
            </div>
        </div>"#
    );

    let bc = format!(r#"<a href="/">Dashboard</a> / <a href="/live/{container}">Live / {container}</a> / {db}"#);
    Html(layout("Live", &bc, &body)).into_response()
}

async fn live_table_data(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((container, db, table)): Path<(String, String, String)>,
    Query(params): Query<PageParams>,
) -> impl IntoResponse {
    if let Some(r) = require_auth(&state, &jar).await { return r.into_response(); }
    let (user, password) = get_container_env(&container);
    let page = params.page.unwrap_or(0);
    let offset = page * PAGE_SIZE;
    let search = params.q.clone().unwrap_or_default();

    // Get columns
    let (schema, tbl) = table.split_once('.').unwrap_or(("public", &table));
    let cols_output = run_psql_query(
        &container, &user, &password, &db,
        &format!("SELECT column_name FROM information_schema.columns WHERE table_schema = '{}' AND table_name = '{}' ORDER BY ordinal_position", schema, tbl),
    ).unwrap_or_default();

    let columns: Vec<String> = cols_output.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();

    // Build WHERE clause for search
    let where_clause = if !search.is_empty() {
        // Sanitize search input for SQL
        let safe_search = search.replace('\'', "''").replace('\\', "\\\\");
        let conditions: Vec<String> = columns.iter().map(|col| {
            format!("CAST(\"{}\" AS TEXT) ILIKE '%{}%'", col.replace('"', "\"\""), safe_search)
        }).collect();
        if conditions.is_empty() {
            String::new()
        } else {
            format!(" WHERE {}", conditions.join(" OR "))
        }
    } else {
        String::new()
    };

    // Get row count
    let count_output = run_psql_query(
        &container, &user, &password, &db,
        &format!("SELECT count(*) FROM {}{}", table, where_clause),
    ).unwrap_or_default();
    let total_rows: usize = count_output.trim().parse().unwrap_or(0);

    // Get page of rows using COPY format (handles newlines in values)
    let data_output = run_psql_query(
        &container, &user, &password, &db,
        &format!("COPY (SELECT * FROM {}{} LIMIT {} OFFSET {}) TO STDOUT", table, where_clause, PAGE_SIZE, offset),
    ).unwrap_or_default();

    let rows: Vec<Vec<String>> = data_output
        .lines()
        .filter(|l| !l.is_empty())
        .map(|line| {
            line.split('\t')
                .map(|v| v.replace("\\n", "\n").replace("\\\\", "\\"))
                .collect()
        })
        .collect();

    let base_url = if search.is_empty() {
        format!("/live/{}/{}/{}", container, db, table)
    } else {
        format!("/live/{}/{}/{}?q={}", container, db, table, urlencoded(&search))
    };
    let body = render_data_table_with_search(&table, &columns, &rows, total_rows, page, &base_url, &search, true);

    let bc = format!(
        r#"<a href="/">Dashboard</a> / <a href="/live/{container}">Live / {container}</a> / <a href="/live/{container}/{db}">{db}</a> / {table}"#
    );
    Html(layout("Live", &bc, &body)).into_response()
}

// --- Help page ---

async fn help_page(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    if let Some(r) = require_auth(&state, &jar).await { return r.into_response(); }

    let body = r#"
    <div class="card">
        <div class="card-header"><span class="card-title">Dashboard</span></div>
        <div class="help-content">
            <h3>Backups</h3>
            <p>The dashboard shows all detected Postgres containers and their backups. Backups run automatically on the schedule you configure in the sidebar.</p>
            <ul>
                <li><strong>Backup All Now</strong> &mdash; triggers an immediate backup of every Postgres container</li>
                <li><strong>Backup</strong> (per container) &mdash; backs up a single container on demand</li>
                <li><strong>Browse</strong> &mdash; view the contents of a backup: select a table to see its columns and paginated rows</li>
                <li><strong>Restore</strong> &mdash; drops all application databases and restores them from the selected backup. Requires confirmation</li>
            </ul>

            <h3>Live View</h3>
            <p>Click <strong>Live</strong> on any container to query the running database directly. Browse databases, tables, and view paginated row data in real time.</p>

            <h3>Configuration</h3>
            <p>The sidebar lets you adjust:</p>
            <ul>
                <li><strong>Start hour / Minute</strong> &mdash; when the first backup of the day runs (UTC)</li>
                <li><strong>Frequency</strong> &mdash; how often backups repeat (hourly to weekly)</li>
                <li><strong>Retention</strong> &mdash; how many backups to keep per container (oldest are deleted automatically)</li>
            </ul>
            <p>Changes take effect immediately &mdash; no restart needed.</p>
        </div>
    </div>

    <div class="card">
        <div class="card-header"><span class="card-title">CLI Commands</span></div>
        <div class="help-content">
            <p>PG-Guard includes CLI tools that can be run directly inside the container:</p>
            <table>
                <thead><tr><th>Command</th><th>Description</th></tr></thead>
                <tbody>
                    <tr><td><code>docker exec pg_guard pg_guard /backups</code></td><td>Back up all Postgres containers</td></tr>
                    <tr><td><code>docker exec pg_guard pg_guard /backups --container my_db</code></td><td>Back up a single container</td></tr>
                    <tr><td><code>docker exec -it pg_guard pg_browse /backups</code></td><td>Browse backups interactively in the terminal</td></tr>
                    <tr><td><code>docker exec -it pg_guard pg_recall /backups</code></td><td>Restore a backup interactively in the terminal</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="card">
        <div class="card-header"><span class="card-title">How It Works</span></div>
        <div class="help-content">
            <ul>
                <li>PG-Guard auto-detects running Postgres containers via the Docker socket</li>
                <li>Credentials are read from each container's <code>POSTGRES_USER</code> and <code>POSTGRES_PASSWORD</code> environment variables</li>
                <li>Backups use <code>pg_dumpall --clean</code> and are stored as timestamped gzipped SQL files</li>
                <li>Restores drop and recreate all application databases before replaying the dump</li>
                <li>Login passwords are hashed with Argon2id &mdash; only the hash is stored, never the plaintext</li>
            </ul>
        </div>
    </div>

    <div class="card donate-card">
        <div class="card-header"><span class="card-title">Support PG-Guard</span></div>
        <div class="help-content">
            <p>PG-Guard is free, open source software built and maintained by an independent developer. If it's saving you time or keeping your data safe, consider supporting its continued development.</p>
            <a href="https://donate.stripe.com/fZu6oHbg026l7EIax2fbq04" target="_blank" rel="noopener" class="donate-btn">Donate</a>
            <p style="margin-top:0.75rem; font-size:0.8rem; text-align:center; color:var(--text-faint)">&mdash; Leon | <a href="https://gilroy.digital/tools" target="_blank" rel="noopener">More tools</a></p>
        </div>
    </div>
    "#;

    let bc = r#"<a href="/">Dashboard</a> / Help"#;
    Html(layout("Help", bc, body)).into_response()
}

// --- API ---

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
    reload: bool,
}

async fn api_backup(State(state): State<AppState>, jar: CookieJar) -> impl IntoResponse {
    if !state.is_authenticated(&jar).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse { success: false, message: "Unauthorized".into(), reload: false })).into_response();
    }
    let _lock = state.busy.lock().await;

    let output = tokio::process::Command::new("pg_guard")
        .arg(&state.backup_dir)
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => Json(ApiResponse {
            success: true,
            message: "Backup completed successfully.".into(),
            reload: true,
        }).into_response(),
        Ok(o) => Json(ApiResponse {
            success: false,
            message: format!("Backup failed: {}", String::from_utf8_lossy(&o.stderr)),
            reload: false,
        }).into_response(),
        Err(e) => Json(ApiResponse {
            success: false,
            message: format!("Failed to start backup: {}", e),
            reload: false,
        }).into_response(),
    }
}

async fn api_backup_container(
    State(state): State<AppState>,
    jar: CookieJar,
    Path(container): Path<String>,
) -> impl IntoResponse {
    if !state.is_authenticated(&jar).await {
        return Json(ApiResponse { success: false, message: "Unauthorized".into(), reload: false }).into_response();
    }
    let _lock = state.busy.lock().await;

    let output = tokio::process::Command::new("pg_guard")
        .arg(&state.backup_dir)
        .arg("--container")
        .arg(&container)
        .output()
        .await;

    match output {
        Ok(o) if o.status.success() => Json(ApiResponse {
            success: true,
            message: format!("Backup of '{}' completed.", container),
            reload: true,
        }).into_response(),
        Ok(o) => Json(ApiResponse {
            success: false,
            message: format!("Backup failed: {}", String::from_utf8_lossy(&o.stderr)),
            reload: false,
        }).into_response(),
        Err(e) => Json(ApiResponse {
            success: false,
            message: format!("Failed to start backup: {}", e),
            reload: false,
        }).into_response(),
    }
}

#[derive(Deserialize)]
struct ConfigUpdate {
    keep_runs: usize,
    schedule_hour: u8,
    schedule_minute: u8,
    interval_hours: u32,
    backups_enabled: bool,
}

async fn api_config_update(
    State(state): State<AppState>,
    jar: CookieJar,
    Json(update): Json<ConfigUpdate>,
) -> impl IntoResponse {
    if !state.is_authenticated(&jar).await {
        return Json(ApiResponse { success: false, message: "Unauthorized".into(), reload: false }).into_response();
    }
    if update.schedule_hour > 23 {
        return Json(ApiResponse { success: false, message: "Hour must be 0-23".into(), reload: false }).into_response();
    }
    if update.schedule_minute > 59 {
        return Json(ApiResponse { success: false, message: "Minute must be 0-59".into(), reload: false }).into_response();
    }
    if update.interval_hours == 0 {
        return Json(ApiResponse { success: false, message: "Interval must be at least 1 hour".into(), reload: false }).into_response();
    }
    if update.keep_runs == 0 {
        return Json(ApiResponse { success: false, message: "Must keep at least 1 backup".into(), reload: false }).into_response();
    }

    {
        let mut config = state.config.write().await;
        config.keep_runs = update.keep_runs;
        config.schedule_hour = update.schedule_hour;
        config.schedule_minute = update.schedule_minute;
        config.interval_hours = update.interval_hours;
        config.backups_enabled = update.backups_enabled;
        save_config(&state.backup_dir, &config);
    }

    let _ = state.schedule_notify.send(());

    Json(ApiResponse {
        success: true,
        message: "Settings saved.".into(),
        reload: true,
    }).into_response()
}

async fn api_restore(
    State(state): State<AppState>,
    jar: CookieJar,
    Path((container, filename)): Path<(String, String)>,
) -> impl IntoResponse {
    if !state.is_authenticated(&jar).await {
        return (StatusCode::UNAUTHORIZED, Json(ApiResponse { success: false, message: "Unauthorized".into(), reload: false })).into_response();
    }
    let _lock = state.busy.lock().await;

    let path = std::path::Path::new(&state.backup_dir)
        .join(&container)
        .join(&filename);
    let file = match std::fs::File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            return (
                StatusCode::NOT_FOUND,
                Json(ApiResponse {
                    success: false,
                    message: format!("Backup not found: {}", e),
                    reload: false,
                }),
            ).into_response()
        }
    };

    let mut decoder = GzDecoder::new(file);
    let mut sql = Vec::new();
    if let Err(e) = decoder.read_to_end(&mut sql) {
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to decompress: {}", e),
                reload: false,
            }),
        ).into_response();
    }

    let (user, password) = get_container_env(&container);

    // Find databases to drop
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

    // Drop databases
    for db in &databases {
        let drop_sql = format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '{db}';\nDROP DATABASE IF EXISTS \"{db}\";",
        );
        let _ = Command::new("docker")
            .args(["exec", "-i", "-e"])
            .arg(format!("PGPASSWORD={}", password))
            .arg(&container)
            .args(["psql", "-U", &user, "-d", "postgres"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                if let Some(stdin) = child.stdin.as_mut() {
                    use std::io::Write;
                    let _ = stdin.write_all(drop_sql.as_bytes());
                }
                child.wait_with_output()
            });
    }

    // Restore
    let restore_result = Command::new("docker")
        .args(["exec", "-i", "-e"])
        .arg(format!("PGPASSWORD={}", password))
        .arg(&container)
        .args([
            "psql",
            "-U",
            &user,
            "-d",
            "postgres",
            "--set",
            "ON_ERROR_STOP=off",
        ])
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .and_then(|mut child| {
            if let Some(stdin) = child.stdin.as_mut() {
                use std::io::Write;
                let _ = stdin.write_all(&sql);
            }
            child.wait_with_output()
        });

    match restore_result {
        Ok(_) => (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Restored {} from {}", container, filename),
                reload: false,
            }),
        ).into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Restore failed: {}", e),
                reload: false,
            }),
        ).into_response(),
    }
}

// --- Scheduler ---

async fn run_scheduler(state: AppState) {
    let mut rx = state.schedule_notify.subscribe();

    loop {
        let config = state.config.read().await.clone();

        if !config.backups_enabled {
            println!("Scheduler: backups disabled, waiting for config change...");
            let _ = rx.changed().await;
            println!("Scheduler: config changed, rechecking...");
            continue;
        }

        let sleep_secs = compute_sleep_secs(config.schedule_hour, config.schedule_minute, config.interval_hours);

        println!(
            "Scheduler: next backup in {}h {}m (every {}h starting {:02}:{:02})",
            sleep_secs / 3600,
            (sleep_secs % 3600) / 60,
            config.interval_hours,
            config.schedule_hour,
            config.schedule_minute,
        );

        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(sleep_secs)) => {
                println!("Scheduler: running backup...");
                let output = tokio::process::Command::new("pg_guard")
                    .arg(&state.backup_dir)
                    .output()
                    .await;
                match output {
                    Ok(o) if o.status.success() => println!("Scheduler: backup complete."),
                    Ok(o) => eprintln!("Scheduler: backup failed: {}", String::from_utf8_lossy(&o.stderr)),
                    Err(e) => eprintln!("Scheduler: failed to start backup: {}", e),
                }
            }
            _ = rx.changed() => {
                println!("Scheduler: config changed, recalculating...");
            }
        }
    }
}

fn compute_sleep_secs(hour: u8, minute: u8, interval_hours: u32) -> u64 {
    let now = chrono::Utc::now();
    let today = now.date_naive();
    let target_time =
        chrono::NaiveTime::from_hms_opt(hour as u32, minute as u32, 0).unwrap();
    let mut next = today.and_time(target_time);
    let now_naive = now.naive_utc();

    while next <= now_naive {
        next += chrono::Duration::hours(interval_hours as i64);
    }

    let diff = next - now_naive;
    diff.num_seconds().max(1) as u64
}

// --- Main ---

fn print_banner() {
    println!();
    println!("  ╔══════════════════════════════════════════════════════════════════╗");
    println!("  ║                       PG-Guard is running                       ║");
    println!("  ╠══════════════════════════════════════════════════════════════════╣");
    println!("  ║                                                                  ║");
    println!("  ║  Web UI:  http://localhost:3690                                   ║");
    println!("  ║                                                                  ║");
    println!("  ║  CLI:                                                            ║");
    println!("  ║    docker exec pg_guard pg_guard /backups           Backup all   ║");
    println!("  ║    docker exec pg_guard pg_guard /backups --container <name>     ║");
    println!("  ║    docker exec -it pg_guard pg_browse /backups      Browse       ║");
    println!("  ║    docker exec -it pg_guard pg_recall /backups      Restore      ║");
    println!("  ║                                                                  ║");
    println!("  ╚══════════════════════════════════════════════════════════════════╝");
    println!();
}

#[tokio::main]
async fn main() {
    let backup_dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/backups".to_string());

    let _ = std::fs::create_dir_all(&backup_dir);

    let config = load_config(&backup_dir);
    let (tx, _rx) = watch::channel(());

    let state = AppState {
        backup_dir,
        busy: Arc::new(Mutex::new(())),
        config: Arc::new(RwLock::new(config)),
        schedule_notify: tx,
        sessions: Arc::new(RwLock::new(HashSet::new())),
    };

    // Start scheduler
    let sched_state = state.clone();
    tokio::spawn(async move {
        run_scheduler(sched_state).await;
    });

    let app = Router::new()
        // Auth
        .route("/setup", get(setup_page).post(setup_submit))
        .route("/login", get(login_page).post(login_submit))
        .route("/logout", post(logout))
        // Pages
        .route("/", get(dashboard))
        .route("/help", get(help_page))
        .route("/browse/{container}/{filename}", get(browse_tables))
        .route("/browse/{container}/{filename}/{table}", get(browse_table_data))
        .route("/live/{container}", get(live_databases))
        .route("/live/{container}/{db}", get(live_tables))
        .route("/live/{container}/{db}/{table}", get(live_table_data))
        // API
        .route("/api/backup", post(api_backup))
        .route("/api/backup/{container}", post(api_backup_container))
        .route("/api/config", post(api_config_update))
        .route("/api/restore/{container}/{filename}", post(api_restore))
        .with_state(state);

    print_banner();

    let addr = "0.0.0.0:3690";
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

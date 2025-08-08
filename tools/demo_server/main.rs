use std::{net::SocketAddr, path::{Path, PathBuf}};

use axum::{
    extract::{DefaultBodyLimit, Multipart, Path as AxPath, Query, WebSocketUpgrade},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use axum::extract::ws::{Message, WebSocket};
use serde::{Deserialize, Serialize};
use tower_http::{cors::CorsLayer, trace::TraceLayer, limit::RequestBodyLimitLayer, services::ServeDir};
use tracing::{error, info};

#[derive(Debug, Serialize, Deserialize)]
struct ScanQuery {
    format: Option<String>,
    emit_cfg: Option<bool>,
}

#[derive(Debug, Serialize, Deserialize)]
struct ValidateRulesReq { yaml: String }

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info")
        .init();

    let app = Router::new()
        .route("/api/scan", post(scan))
        .route("/api/validate-rules", post(validate_rules))
        .route("/api/samples", get(list_samples))
        .route("/api/samples/:id/scan", get(scan_sample))
        .route("/api/terminal", get(terminal_ws))
        .fallback_service(ServeDir::new("tools/demo_server").append_index_html_on_directories(true))
        .layer(CorsLayer::permissive())
        .layer(TraceLayer::new_for_http())
        .layer(RequestBodyLimitLayer::new(1 * 1024 * 1024))
        .layer(DefaultBodyLimit::max(1 * 1024 * 1024));

    let addr: SocketAddr = "0.0.0.0:8080".parse().unwrap();
    info!("listening" = %addr);
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app.into_make_service())
        .await
        .unwrap();
}

fn is_elf(bytes: &[u8]) -> bool { bytes.len() > 4 && &bytes[0..4] == b"\x7FELF" }

async fn scan(mut multipart: Multipart) -> Result<impl IntoResponse, Response> {
    let mut file_bytes: Option<Vec<u8>> = None;
    let mut filename: Option<String> = None;
    let mut build = false;
    let mut format = String::from("table");
    let mut rules_yaml: Option<String> = None;

    while let Some(field) = multipart.next_field().await.map_err(internal_error)? {
        let name = field.name().unwrap_or("").to_string();
        match name.as_str() {
            "file" => {
                filename = field.file_name().map(|s| s.to_string());
                let data = field.bytes().await.map_err(bad_request)?;
                if data.len() > 1_000_000 { return Err(bad_request_err("File too large")); }
                file_bytes = Some(data.to_vec());
            }
            "build" => {
                let val = field.text().await.map_err(bad_request)?;
                build = matches!(val.as_str(), "1" | "true" | "on");
            }
            "format" => {
                let val = field.text().await.map_err(bad_request)?;
                if val == "json" { format = "json".into(); }
            }
            "rules" => {
                let val = field.text().await.map_err(bad_request)?;
                if !val.trim().is_empty() { rules_yaml = Some(val); }
            }
            _ => {}
        }
    }

    let file_bytes = file_bytes.ok_or_else(|| bad_request_err("Missing file"))?;
    let filename = filename.unwrap_or_else(|| "upload.o".into());

    // Basic sniffing: .o should be ELF, .c should be text
    let is_c = filename.ends_with('.').then(|| false).unwrap_or(false) || filename.ends_with(".c");
    if !is_c && !is_elf(&file_bytes) {
        return Err(bad_request_err("Provided file is not a valid ELF object"));
    }

    let tmpdir = tempfile::tempdir().map_err(internal_error)?;
    let mut input_path = tmpdir.path().join(&filename);
    tokio::fs::write(&input_path, &file_bytes).await.map_err(internal_error)?;

    // Optional build step if .c and build requested
    if filename.ends_with(".c") {
        if build {
            match ebpf_guardian::builder::build_bpf_program(&input_path, None, 2).await {
                Ok(obj_path) => { input_path = obj_path; }
                Err(e) => return Err(bad_request_err(&format!("Build failed: {e}")))
            }
        } else {
            return Err(bad_request_err(".c upload requires build=true"));
        }
    }

    // Write rules if provided
    let rules_path_opt: Option<PathBuf> = if let Some(yaml) = rules_yaml {
        let rp = tmpdir.path().join("rules.yaml");
        tokio::fs::write(&rp, yaml).await.map_err(internal_error)?;
        Some(rp)
    } else {
        None
    };

    // Run analysis
    let summary = ebpf_guardian::analyze_bpf_program(&input_path, rules_path_opt.as_deref()).await
        .map_err(|e| bad_request_err(&format!("Analyze failed: {e}")))?;

    if format == "json" {
        return Ok((StatusCode::OK, Json(summary)).into_response());
    }

    // Human-readable formatting using existing formatter
    let out = ebpf_guardian::output::formatter::format_output(&summary, &crate_cli_format("table"))
        .map_err(internal_error)?;
    Ok((StatusCode::OK, out).into_response())
}

async fn validate_rules(Json(req): Json<ValidateRulesReq>) -> Result<impl IntoResponse, Response> {
    let _: Vec<ebpf_guardian::analyzer::rule_engine::Rule> = serde_yaml::from_str(&req.yaml)
        .map_err(|e| bad_request_err(&format!("Invalid YAML: {e}")))?;
    Ok((StatusCode::OK, Json(serde_json::json!({"ok": true}))))
}

#[derive(Serialize)]
struct SampleInfo { id: String, filename: String, description: String }

async fn list_samples() -> impl IntoResponse {
    let samples = vec![
        SampleInfo { id: "simple".into(), filename: "tests/data/simple.o".into(), description: "Simple test object".into() },
        SampleInfo { id: "xdp_counter".into(), filename: "eBPF_sample_programs/xdp_counter.o".into(), description: "XDP counter program".into() },
        SampleInfo { id: "syscall_trace".into(), filename: "eBPF_sample_programs/syscall_trace.o".into(), description: "Kprobe syscall trace".into() },
        SampleInfo { id: "socket_filter".into(), filename: "eBPF_sample_programs/socket_filter.o".into(), description: "Socket filter example".into() },
    ];
    Json(samples)
}

async fn scan_sample(AxPath(id): AxPath<String>, Query(q): Query<ScanQuery>) -> Result<impl IntoResponse, Response> {
    let file = match id.as_str() {
        "simple" => "tests/data/simple.o",
        "xdp_counter" => "eBPF_sample_programs/xdp_counter.o",
        "syscall_trace" => "eBPF_sample_programs/syscall_trace.o",
        "socket_filter" => "eBPF_sample_programs/socket_filter.o",
        _ => return Err((StatusCode::NOT_FOUND, "Unknown sample").into_response()),
    };
    let path = Path::new(file);
    let summary = ebpf_guardian::analyze_bpf_program(path, None).await
        .map_err(|e| internal_error(e))
        .map_err(|e| e.into_response())?;
    if q.format.as_deref() == Some("json") {
        return Ok(Json(summary).into_response());
    }
    let out = ebpf_guardian::output::formatter::format_output(&summary, &crate_cli_format("table")).map_err(internal_error).map_err(|e| e.into_response())?;
    Ok(out.into_response())
}

fn crate_cli_format(s: &str) -> ebpf_guardian::cli::OutputFormat {
    // Reuse CLI enum by parsing known strings
    match s {
        "json" => ebpf_guardian::cli::OutputFormat::Json,
        _ => ebpf_guardian::cli::OutputFormat::Table,
    }
}

fn internal_error<E: std::fmt::Display>(e: E) -> Response {
    error!(error = %e, "internal error");
    (StatusCode::INTERNAL_SERVER_ERROR, format!("internal error: {e}")).into_response()
}

fn bad_request<E: std::fmt::Display>(e: E) -> Response {
    (StatusCode::BAD_REQUEST, format!("bad request: {e}")).into_response()
}

fn bad_request_err(msg: &str) -> Response {
    (StatusCode::BAD_REQUEST, msg.to_string()).into_response()
}

async fn terminal_ws(ws: WebSocketUpgrade) -> impl IntoResponse {
    ws.on_upgrade(handle_terminal)
}

async fn handle_terminal(mut socket: WebSocket) {
    // Greet
    let _ = socket.send(Message::Text("Welcome to ebguard demo terminal. Allowed: ebguard scan ..., ebguard validate-rules ...".into())).await;

    while let Some(Ok(msg)) = socket.recv().await {
        let Some(line) = msg.to_text().ok() else { continue };
        let line = line.trim();
        if line.is_empty() { continue; }
        // Simple router for known commands
        if let Some(rest) = line.strip_prefix("ebguard scan ") {
            if let Err(e) = ws_cmd_scan(&mut socket, rest).await { let _ = socket.send(Message::Text(format!("error: {e}"))).await; }
            continue;
        }
        if let Some(rest) = line.strip_prefix("ebguard validate-rules ") {
            if let Err(e) = ws_cmd_validate(&mut socket, rest).await { let _ = socket.send(Message::Text(format!("error: {e}"))).await; }
            continue;
        }
        let _ = socket.send(Message::Text("Unsupported command".into())).await;
    }
}

async fn ws_cmd_scan(ws: &mut WebSocket, args: &str) -> anyhow::Result<()> {
    // Very small parser: --file sample:<id>|path --format json|table
    let mut file: Option<String> = None;
    let mut format = "table".to_string();
    // Accept patterns "--file sample:<id>" and optional "--format json"
    let parts: Vec<&str> = args.split_whitespace().collect();
    let mut i = 0;
    while i < parts.len() {
        match parts[i] {
            "--file" => { i += 1; if i < parts.len() { file = Some(parts[i].to_string()); } }
            "--format" => { i += 1; if i < parts.len() { format = parts[i].to_string(); } }
            _ => {}
        }
        i += 1;
    }
    let Some(file_arg) = file else { ws.send(Message::Text("missing --file".into())).await.ok(); return Ok(()); };
    if let Some(id) = file_arg.strip_prefix("sample:") {
        // route to sample
        let url = if format == "json" { format!("/api/samples/{id}/scan?format=json") } else { format!("/api/samples/{id}/scan") };
        ws.send(Message::Text(format!("GET {url}"))).await.ok();
        // In-process call
        let query = ScanQuery { format: Some(format.clone()), emit_cfg: None };
        let file = match id {
            "simple" => "tests/data/simple.o",
            "xdp_counter" => "eBPF_sample_programs/xdp_counter.o",
            "syscall_trace" => "eBPF_sample_programs/syscall_trace.o",
            "socket_filter" => "eBPF_sample_programs/socket_filter.o",
            _ => { ws.send(Message::Text("unknown sample".into())).await.ok(); return Ok(()); }
        };
        let path = Path::new(file);
        let summary = ebpf_guardian::analyze_bpf_program(path, None).await?;
        if format == "json" { ws.send(Message::Text(serde_json::to_string_pretty(&summary)?)).await.ok(); }
        else {
            let out = ebpf_guardian::output::formatter::format_output(&summary, &crate_cli_format("table"))?;
            ws.send(Message::Text(out)).await.ok();
        }
        return Ok(());
    }
    ws.send(Message::Text("only sample:<id> supported in WS demo".into())).await.ok();
    Ok(())
}

async fn ws_cmd_validate(ws: &mut WebSocket, _args: &str) -> anyhow::Result<()> {
    ws.send(Message::Text("usage: ebguard validate-rules --file sample rules not supported in WS".into())).await.ok();
    Ok(())
}


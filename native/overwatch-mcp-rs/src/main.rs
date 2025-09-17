use anyhow::Result;
use clap::{ArgAction, Parser};
use rmcp::{
    tool_handler,
    handler::server::tool::ToolRouter,
    handler::server::ServerHandler,
    model::{CallToolResult, Content, ServerInfo, Implementation},
    tool, tool_router,
    service::serve_server,
    ErrorData as McpError,
};
use sysinfo::{Disks, System, Components};
use tokio::io::{stdin, stdout};
// no tracing in stdio mode to avoid stdout contamination
use std::future::Future;

/// Overwatch MCP (Rust) - Minimal server (stdio)
#[derive(Parser, Debug)]
#[command(author, version, about)]
struct Cli {
    /// Usar transporte stdio (recomendado para integración con FastAPI)
    #[arg(long, action = ArgAction::SetTrue)]
    stdio: bool,

    /// (Planificado) WebSocket bind, ejemplo: 127.0.0.1:8822
    #[arg(long)]
    _ws: Option<String>,
}

#[derive(Clone)]
struct OverwatchServer {
    tool_router: ToolRouter<Self>,
}

#[tool_router]
impl OverwatchServer {
    fn new() -> Self {
        Self {
            tool_router: Self::tool_router(),
        }
    }

    /// metrics.get: resumen rápido de CPU/Mem/Disks
    #[tool(name = "metrics.get", description = "Obtener métricas rápidas del sistema (CPU/Mem/Disks)")]
    async fn metrics_get(&self) -> Result<CallToolResult, McpError> {
        let mut sys = System::new();
        sys.refresh_memory();
        sys.refresh_cpu_usage();
        let disks = Disks::new_with_refreshed_list();

        let total_mem = sys.total_memory();
        let used_mem = sys.used_memory();
        let cpu_usage = sys.global_cpu_info().cpu_usage();

        let mut total_disk = 0u64;
        let mut used_disk = 0u64;
        for d in &disks {
            total_disk = total_disk.saturating_add(d.total_space());
            used_disk = used_disk.saturating_add(d.total_space().saturating_sub(d.available_space()));
        }

        let payload = serde_json::json!({
            "cpu": { "usage": cpu_usage },
            "memory": { "total": total_mem, "used": used_mem },
            "disks": { "total": total_disk, "used": used_disk },
        });

        Ok(CallToolResult::success(vec![Content::text(payload.to_string())]))
    }

    /// process.list: lista corta de procesos (PID, nombre, cpu, mem)
    #[tool(name = "process.list", description = "Listar procesos (top 10 aproximado)")]
    async fn process_list(&self) -> Result<CallToolResult, McpError> {
        let mut sys = System::new();
        sys.refresh_processes();

        let mut procs: Vec<_> = sys
            .processes()
            .iter()
            .map(|(pid, p)| {
                serde_json::json!({
                    "pid": pid.as_u32(),
                    "name": p.name(),
                    "cpu": p.cpu_usage(),
                    "mem": p.memory(),
                })
            })
            .collect();

        // ordenar por CPU desc y limitar a 10
        procs.sort_by(|a, b| {
            let ac = a.get("cpu").and_then(|v| v.as_f64()).unwrap_or(0.0);
            let bc = b.get("cpu").and_then(|v| v.as_f64()).unwrap_or(0.0);
            bc.total_cmp(&ac)
        });
        if procs.len() > 10 { procs.truncate(10); }

        let payload = serde_json::json!({ "processes": procs });
        Ok(CallToolResult::success(vec![Content::text(payload.to_string())]))
    }

    /// sensors.get: temperaturas CPU/GPU (best-effort)
    #[tool(name = "sensors.get", description = "Obtener temperaturas CPU/GPU (best-effort, puede devolver nulls)")]
    async fn sensors_get(&self) -> Result<CallToolResult, McpError> {
        // sysinfo Components puede o no exponer sensores en Windows; devolvemos nulls si no hay datos
        let comps = Components::new_with_refreshed_list();
        let mut cpu_temp: Option<f32> = None;
        let mut gpu_temp: Option<f32> = None;

        for c in &comps {
            let label = c.label().to_lowercase();
            let t = c.temperature();
            if label.contains("cpu") || label.contains("package") || label.contains("tdie") {
                cpu_temp = Some(cpu_temp.map_or(t, |v| v.max(t)));
            }
            if label.contains("gpu") || label.contains("nvidia") || label.contains("radeon") || label.contains("intel") {
                gpu_temp = Some(gpu_temp.map_or(t, |v| v.max(t)));
            }
        }

        let payload = serde_json::json!({
            "cpu": { "temp_c": cpu_temp.map(|v| v as f64) },
            "gpu": { "temp_c": gpu_temp.map(|v| v as f64) },
        });

        Ok(CallToolResult::success(vec![Content::text(payload.to_string())]))
    }
}

#[tool_handler]
impl ServerHandler for OverwatchServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            server_info: Implementation {
                name: "Overwatch MCP (Rust)".into(),
                version: env!("CARGO_PKG_VERSION").into(),
                ..Default::default()
            },
            // capabilities: default (tool routing handled by #[tool_handler])
            ..Default::default()
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let server = OverwatchServer::new();

    let use_stdio = cli.stdio || std::env::var_os("OVERWATCH_MCP_STDIO").is_some();
    if use_stdio {
        let transport = (stdin(), stdout());
        let running = serve_server(server, transport).await?;
        let _ = running.waiting().await;
        return Ok(());
    }

    // WS pendiente para siguiente iteración
    tracing::error!("No se especificó transporte soportado. Use --stdio");
    Ok(())
}

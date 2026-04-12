//! SINE Engine — standalone gRPC service on loopback :50053 (PRD-08).
//! Loads Mistral-7B-Instruct Q4_K_M GGUF via llama.cpp; returns allow + reasoning.

use mimalloc::MiMalloc;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

mod llm;

tonic::include_proto!("sine");

use anyhow::{Context, Result};
use llm::SineLlm;
use sine_engine_server::{SineEngine, SineEngineServer};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

const MAX_PAYLOAD_SIZE: usize = 4096;
/// Unary RPC may run long while the model generates; Core uses a 50ms client timeout and fail-open.
const SERVER_RPC_TIMEOUT_SECS: u64 = 600;

pub struct SineService {
    llm: Arc<Mutex<SineLlm>>,
}

#[tonic::async_trait]
impl SineEngine for SineService {
    async fn filter(
        &self,
        request: Request<SineRequest>,
    ) -> Result<Response<SineResponse>, Status> {
        let req = request.into_inner();
        let payload = req.payload;

        if payload.is_empty() {
            return Ok(Response::new(SineResponse {
                allowed: false,
                reasoning: "empty payload".into(),
            }));
        }

        if payload.len() > MAX_PAYLOAD_SIZE {
            return Ok(Response::new(SineResponse {
                allowed: false,
                reasoning: "payload too large".into(),
            }));
        }

        let inner = Arc::clone(&self.llm);
        let blob = payload.clone();
        let outcome = tokio::task::spawn_blocking(move || -> Result<(bool, String), anyhow::Error> {
            let mut guard = inner
                .lock()
                .map_err(|_| anyhow::anyhow!("SINE model mutex poisoned"))?;
            guard.filter_payload(&blob)
        })
        .await
        .map_err(|e| Status::internal(format!("inference task join: {e}")))?;

        let (allowed, reasoning) =
            outcome.map_err(|e| Status::internal(e.to_string()))?;

        Ok(Response::new(SineResponse {
            allowed,
            reasoning,
        }))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let llm = SineLlm::from_env_or_default().context("SINE model load failed")?;
    let service = SineService {
        llm: Arc::new(Mutex::new(llm)),
    };

    let addr: SocketAddr = std::env::var("RANSOMEYE_SINE_ADDR")
        .map_err(|_| anyhow::anyhow!("SINE_ADDR_NOT_SET"))?
        .parse()
        .context("bind address parse failed")?;
    if !addr.is_ipv4() || !addr.ip().is_loopback() {
        anyhow::bail!("NON_LOOPBACK_REJECTED");
    }

    Server::builder()
        .timeout(std::time::Duration::from_secs(SERVER_RPC_TIMEOUT_SECS))
        .add_service(
            SineEngineServer::new(service).max_decoding_message_size(MAX_PAYLOAD_SIZE),
        )
        .serve(addr)
        .await
        .context("SINE Engine server failed")?;

    Ok(())
}

//! Mistral-7B Q4_K_M (GGUF) inference via llama.cpp (PRD-08).

use anyhow::{Context, Result};
use encoding_rs::UTF_8;
use llama_cpp_2::context::params::LlamaContextParams;
use llama_cpp_2::llama_backend::LlamaBackend;
use llama_cpp_2::llama_batch::LlamaBatch;
use llama_cpp_2::model::params::LlamaModelParams;
use llama_cpp_2::model::AddBos;
use llama_cpp_2::model::LlamaModel;
use llama_cpp_2::sampling::LlamaSampler;
use std::num::NonZeroU32;
use std::path::Path;

/// Default PRD-08 canonical path (Mistral-7B-Instruct Q4_K_M GGUF).
pub const DEFAULT_MODEL_PATH: &str = "/opt/ransomeye/sine-engine/models/sine/model.gguf";

pub struct SineLlm {
    backend: LlamaBackend,
    model: LlamaModel,
    n_threads: i32,
    n_ctx: NonZeroU32,
    max_gen_tokens: i32,
    sampler_seed: u32,
}

impl SineLlm {
    pub fn from_env_or_default() -> Result<Self> {
        let path = std::env::var("RANSOMEYE_SINE_MODEL_PATH").unwrap_or_else(|_| DEFAULT_MODEL_PATH.to_string());
        Self::load(Path::new(&path))
    }

    pub fn load(model_path: &Path) -> Result<Self> {
        let backend = LlamaBackend::init().map_err(|e| anyhow::anyhow!("llama backend: {e:?}"))?;

        let model_params = LlamaModelParams::default();
        let model = LlamaModel::load_from_file(&backend, model_path, &model_params).with_context(|| {
            format!(
                "load GGUF model from {} (expect Mistral-7B Q4_K_M per PRD-08)",
                model_path.display()
            )
        })?;

        let n_threads: i32 = std::env::var("RANSOMEYE_SINE_THREADS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(4)
            .clamp(1, 128);

        let n_ctx = NonZeroU32::new(
            std::env::var("RANSOMEYE_SINE_N_CTX")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(2048),
        )
        .context("SINE n_ctx must be non-zero")?;

        let max_gen_tokens: i32 = std::env::var("RANSOMEYE_SINE_MAX_GEN")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(128)
            .clamp(16, 512);

        let sampler_seed: u32 = std::env::var("RANSOMEYE_SINE_SAMPLER_SEED")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(42);

        Ok(Self {
            backend,
            model,
            n_threads,
            n_ctx,
            max_gen_tokens,
            sampler_seed,
        })
    }

    /// Produce narrative + allow/block decision for telemetry bytes (canonical v1 or opaque).
    pub fn filter_payload(&mut self, payload: &[u8]) -> Result<(bool, String)> {
        if payload.is_empty() {
            return Ok((false, "empty payload".into()));
        }

        let take = payload.len().min(384);
        let hex = hex::encode(&payload[..take]);

        let prompt_body = format!(
            "You are SINE (Security Inference & Narrative Engine). Decide if this raw telemetry should be forwarded to the AI threat-analysis engine.\n\
Telemetry (hex, may be truncated):\n\
{hex}\n\n\
Reply with exactly two lines. Line 1: ALLOW or BLOCK in uppercase. Line 2: one short forensic sentence explaining why."
        );

        // Mistral-Instruct delimiter (PRD-08 / common deployment pattern).
        let prompt = format!("<s>[INST] {prompt_body} [/INST]");

        let ctx_params = LlamaContextParams::default()
            .with_n_ctx(Some(self.n_ctx))
            .with_n_threads(self.n_threads)
            .with_n_threads_batch(self.n_threads);

        let mut ctx = self
            .model
            .new_context(&self.backend, ctx_params)
            .map_err(|e| anyhow::anyhow!("llama context: {e:?}"))?;

        let tokens_list = self
            .model
            .str_to_token(prompt.as_str(), AddBos::Never)
            .map_err(|e| anyhow::anyhow!("tokenize: {e:?}"))?;

        let n_ctx_i = ctx.n_ctx() as i32;
        let n_len = self.max_gen_tokens + tokens_list.len() as i32;
        if n_len > n_ctx_i {
            anyhow::bail!("prompt too large for n_ctx");
        }

        let mut batch = LlamaBatch::new(512, 1);
        let last_index: i32 = (tokens_list.len() - 1) as i32;
        for (i, token) in (0_i32..).zip(tokens_list.into_iter()) {
            let is_last = i == last_index;
            batch.add(token, i, &[0], is_last)?;
        }

        ctx.decode(&mut batch).map_err(|e| anyhow::anyhow!("decode prompt: {e:?}"))?;

        let mut n_cur = batch.n_tokens();
        let mut sampler =
            LlamaSampler::chain_simple([LlamaSampler::dist(self.sampler_seed), LlamaSampler::greedy()]);

        let mut decoder = UTF_8.new_decoder();
        let mut out = String::new();

        let gen_cap = n_cur + self.max_gen_tokens;
        while n_cur < gen_cap {
            let token = sampler.sample(&ctx, batch.n_tokens() - 1);
            sampler.accept(token);

            if self.model.is_eog_token(token) {
                break;
            }

            let piece = self
                .model
                .token_to_piece(token, &mut decoder, true, None)
                .map_err(|e| anyhow::anyhow!("token_to_piece: {e:?}"))?;
            out.push_str(&piece);

            batch.clear();
            batch.add(token, n_cur, &[0], true)?;
            n_cur += 1;

            ctx.decode(&mut batch).map_err(|e| anyhow::anyhow!("decode step: {e:?}"))?;
        }

        let (allowed, reasoning) = parse_allow_line(&out);
        Ok((allowed, reasoning))
    }
}

fn parse_allow_line(text: &str) -> (bool, String) {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let first = lines.next().unwrap_or("ALLOW").to_uppercase();
    let rest: String = lines.collect::<Vec<_>>().join(" ");

    let allowed = if first.starts_with("BLOCK") {
        false
    } else if first.starts_with("ALLOW") {
        true
    } else {
        !first.contains("BLOCK")
    };

    let reasoning = if rest.is_empty() {
        text.trim().lines().last().unwrap_or("no model narrative").to_string()
    } else {
        rest
    };

    (allowed, reasoning)
}

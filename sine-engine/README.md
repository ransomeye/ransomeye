# SINE Engine (PRD-08)

Standalone gRPC service: **Mistral-7B-Instruct Q4_K_M** GGUF via **llama.cpp** (Rust `llama-cpp-2`). Binds **127.0.0.1:50053** only (loopback, mTLS gRPC).

## Build

Host toolchain:

- Rust 1.78+
- `cmake`, C/C++17 (`cc` / `c++`)
- `protoc` (for `tonic-build`)
- `libclang` / GCC headers for `bindgen` (if `stdbool.h` not found, set `BINDGEN_EXTRA_CLANG_ARGS="-I/usr/lib/gcc/x86_64-linux-gnu/<ver>/include"`)

```bash
cargo build --release
```

Proto: `../proto/sine.proto` (`SineEngine.Filter`).

## Model

Default GGUF path: `/opt/ransomeye/sine-engine/models/sine/model.gguf` (Q4_K_M per PRD-08).

Override:

```bash
export RANSOMEYE_SINE_MODEL_PATH=/path/to/mistral-7b-instruct-q4_k_m.gguf
```

Optional tuning: `RANSOMEYE_SINE_THREADS`, `RANSOMEYE_SINE_N_CTX`, `RANSOMEYE_SINE_MAX_GEN`, `RANSOMEYE_SINE_SAMPLER_SEED`.

## Run

```bash
export RANSOMEYE_SINE_ADDR=127.0.0.1:50053
./target/release/sine-engine
```

## Contract

- **RPC:** `Filter(SineRequest) -> SineResponse { allowed, reasoning }`
- **Binding:** IPv4 loopback only (`NON_LOOPBACK_REJECTED` otherwise)

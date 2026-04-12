fn main() {
    if let Err(e) = tonic_build::configure()
        .build_server(true)
        .compile(&["../proto/sine.proto"], &["../proto"])
    {
        eprintln!("failed to compile sine.proto: {}", e);
        std::process::exit(1);
    }
}

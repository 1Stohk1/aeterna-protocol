fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    // v0.2.0 "Custos" — the signing-path service.
    println!("cargo:rerun-if-changed=../proto/signer.proto");
    // v0.3.0 "Oculus" — the read-only observability service. Mounted
    // on the same listener as `Signer` (see docs/SPRINT-v0.3.0.md §7.1).
    println!("cargo:rerun-if-changed=../proto/admin.proto");

    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(
            &["../proto/signer.proto", "../proto/admin.proto"],
            &["../proto"],
        )?;
    Ok(())
}

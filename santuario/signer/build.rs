fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    println!("cargo:rerun-if-changed=../proto/signer.proto");
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile(&["../proto/signer.proto"], &["../proto"])?;
    Ok(())
}

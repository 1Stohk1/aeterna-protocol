// Generates the Admin gRPC client stub for santuario-exporter.
//
// The exporter is a CLIENT only -- it never serves the Admin RPCs, it
// consumes them. We disable build_server() to keep the generated code
// (and the binary) lean.
//
// We compile only `admin.proto`: the exporter has no business with
// `signer.proto` (which carries the Sign RPC and pulls in Dilithium
// message types). One proto, one client, one focused crate.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);

    println!("cargo:rerun-if-changed=../proto/admin.proto");

    tonic_build::configure()
        .build_server(false)
        .build_client(true)
        .compile(&["../proto/admin.proto"], &["../proto"])?;
    Ok(())
}

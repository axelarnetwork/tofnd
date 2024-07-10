fn main() -> Result<(), Box<dyn std::error::Error>> {
    // TODO: client build is needed only for tests https://github.com/rust-lang/cargo/issues/1581
    tonic_build::configure()
        // .build_client(false)
        // .out_dir(".") // if you want to peek at the generated code
        .compile(&["proto/multisig.proto"], &["proto"])?;
    Ok(())
}

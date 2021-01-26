fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use [`compile_protos`] only if you don't need to tweak anything
    // tonic_build::compile_protos("proto/tofnd.proto")?;

    // client build needed only for tests https://github.com/rust-lang/cargo/issues/1581
    tonic_build::configure()
        // .build_client(false)
        .compile(&["proto/tofnd.proto"], &["proto"])?;
    Ok(())
}

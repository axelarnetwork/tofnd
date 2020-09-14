fn main() -> Result<(), Box<dyn std::error::Error>> {

    // Use [`compile_protos`] only if you don't need to tweak anything
    // tonic_build::compile_protos("proto/tssd.proto")?;

    tonic_build::configure()
    .build_client(false)
    .compile(
        &["proto/tssd.proto"],
        &["proto"],
    )?;
    Ok(())
}

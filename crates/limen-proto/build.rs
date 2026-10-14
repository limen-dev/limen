fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = "../../proto";
    tonic_prost_build::configure().compile_protos(
        &[
            format!("{root}/limen/v1/audit.proto"),
            format!("{root}/limen/v1/control.proto"),
            format!("{root}/limen/v1/tunnel.proto"),
        ],
        &[root.to_owned()],
    )?;
    println!("cargo:rerun-if-changed={root}");
    Ok(())
}

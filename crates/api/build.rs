//! Compiles the gRPC definitions when the Cargo feature `grpc` is on.
//!
//! The build needs no `protoc` program. `protox` is a protobuf compiler in Rust. It makes
//! the file descriptor set that `tonic-prost-build` turns into Rust code.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(feature = "grpc")]
    {
        const PROTO: &str = "proto/aegis/v1/aegis.proto";
        println!("cargo:rerun-if-changed={PROTO}");
        let descriptors = protox::compile([PROTO], ["proto"])?;
        tonic_prost_build::configure()
            .build_transport(false)
            .compile_fds(descriptors)?;
    }
    Ok(())
}

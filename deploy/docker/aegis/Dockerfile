# syntax=docker/dockerfile:1.28.0@sha256:bb22d9815c728170f72750f4e5b0d672e06176142e1d602c7e66c050100b7e5b

# The AEGIS image: the `aegis` program as one static binary on an empty base image.
#
# Build from the root of the repository:
#
#   docker build --file deploy/docker/aegis/Dockerfile --tag aegis:local .
#   docker build --file deploy/docker/aegis/Dockerfile --tag aegis:monitoring-only \
#       --build-arg AEGIS_FEATURES=monitoring-only .
#   docker buildx build --file deploy/docker/aegis/Dockerfile \
#       --platform linux/amd64,linux/arm64 --tag aegis:local --load .
#
# The build machine needs only Docker. The build stages run on the platform of the build
# machine and compile for the target platform. Thus a build for a different processor
# needs no emulator.
#
# Each base image has a tag and a digest. Each digest is a multi-platform index. To change
# a version, change the tag and the digest together. The Rust version of the build image
# must be the version in `rust-toolchain.toml`: the build stops if the two are different.

# The Cargo features of the binary: `full` or `monitoring-only`.
#   full             The default features of `aegis-cli`: postgres, plugins, otlp, and api.
#   monitoring-only  No default features: no PostgreSQL, no plugins, no trace export, and
#                    no HTTP server.
ARG AEGIS_FEATURES=full

# Cross-compilation helpers: `xx-cargo`, `xx-apk`, and `xx-verify`.
FROM --platform=$BUILDPLATFORM tonistiigi/xx:1.10.0@sha256:40fe21f44bb8cddf1eb1226db190d0a984118f62ee02a91b77d99448d28264a6 AS xx

# ---------------------------------------------------------------------------------------
# The toolchain: Rust on Alpine Linux, with a C compiler and a linker for all targets.
# ---------------------------------------------------------------------------------------
FROM --platform=$BUILDPLATFORM rust:1.100.0-alpine3.24@sha256:8d0e82abfdf9a38071e07cabc5afba4ddbe077631a80e4e742a760c38beadc33 AS toolchain

COPY --from=xx / /

# clang and lld compile and link the C code of the dependencies for each target.
# `xx-verify` reads the type of the binary with `file`.
RUN apk add --no-cache clang file lld

# Stop if the Rust version of this image is not the version that the repository pins.
RUN --mount=type=bind,source=rust-toolchain.toml,target=/run/aegis/rust-toolchain.toml \
    pinned="$(sed -n 's/^channel *= *"\([^"]*\)".*$/\1/p' /run/aegis/rust-toolchain.toml)" \
    && installed="$(rustc --version | cut -d ' ' -f 2)" \
    && if [ -z "$pinned" ] || [ "$pinned" != "$installed" ]; then \
           echo "error: rust-toolchain.toml pins Rust '$pinned', but this image has Rust '$installed'." >&2; \
           echo "error: change the tag and the digest of the rust image in this Dockerfile." >&2; \
           exit 1; \
       fi \
    && echo "Rust $installed is the version that rust-toolchain.toml pins."

# cargo-chef builds the dependencies in a layer of their own. A change to the source code
# of AEGIS then compiles only the AEGIS crates.
RUN cargo install cargo-chef --locked --version 0.1.78

WORKDIR /src

# ---------------------------------------------------------------------------------------
# The plan: the list of dependencies. It changes only when a manifest or the lock file
# changes.
# ---------------------------------------------------------------------------------------
FROM toolchain AS plan

COPY Cargo.toml Cargo.lock ./
COPY crates crates
RUN cargo chef prepare --recipe-path /recipe.json

# ---------------------------------------------------------------------------------------
# The build: one statically linked binary for the target platform.
# ---------------------------------------------------------------------------------------
FROM toolchain AS build

ARG TARGETPLATFORM
ARG AEGIS_FEATURES

# The C library headers of the target, and the Rust standard library of the target.
RUN xx-apk add --no-cache gcc musl-dev \
    && xx-cargo --setup-target-triple

# Write the Cargo options of the feature set one time. The two cargo steps read them.
RUN case "$AEGIS_FEATURES" in \
        full) echo "" > /cargo-options ;; \
        monitoring-only) echo "--no-default-features" > /cargo-options ;; \
        *) echo "error: AEGIS_FEATURES must be 'full' or 'monitoring-only'." >&2; exit 1 ;; \
    esac

# No debug data and no symbol table in the binary. `crt-static` is the default of the
# musl targets. The option is here so that the build does not depend on that default.
ENV CARGO_PROFILE_RELEASE_DEBUG=0 \
    CARGO_PROFILE_RELEASE_STRIP=symbols \
    CARGO_INCREMENTAL=0 \
    XX_RUSTFLAGS="-C target-feature=+crt-static"

# The dependencies.
COPY --from=plan /recipe.json /recipe.json
RUN xx-cargo chef cook --release --locked --recipe-path /recipe.json \
        --package aegis-cli $(cat /cargo-options)

# The AEGIS crates, and the files that they embed at compile time.
COPY Cargo.toml Cargo.lock ./
COPY crates crates
COPY detections detections
COPY policies policies
COPY playbooks playbooks
COPY fixtures fixtures
COPY wit wit
RUN xx-cargo build --release --locked --package aegis-cli --bin aegis $(cat /cargo-options)

# The root file system of the image. The build stops if the binary is for a different
# platform, or if it is not statically linked.
COPY LICENSE /rootfs/usr/share/licenses/aegis/LICENSE
RUN binary="target/$(xx-cargo --print-target-triple)/release/aegis" \
    && xx-verify --static "$binary" \
    && description="$(file --brief "$binary")" \
    && echo "aegis: $description" \
    && if echo "$description" | grep -E -q 'dynamically linked|interpreter'; then \
           echo "error: the binary is not statically linked." >&2; \
           exit 1; \
       fi \
    && install -D -m 0555 "$binary" /rootfs/aegis \
    && install -D -m 0444 /etc/ssl/certs/ca-certificates.crt /rootfs/etc/ssl/certs/ca-certificates.crt \
    && install -d -m 0755 -o 65532 -g 65532 /rootfs/etc/aegis /rootfs/plugins \
    && install -d -m 0700 -o 65532 -g 65532 /rootfs/var/lib/aegis \
    && install -d -m 1777 /rootfs/tmp

# ---------------------------------------------------------------------------------------
# The image: the binary, the CA certificates, the license, and four empty directories.
# It has no shell, no package manager, and no C library.
# ---------------------------------------------------------------------------------------
FROM scratch AS runtime

ARG AEGIS_FEATURES

LABEL org.opencontainers.image.title="aegis" \
      org.opencontainers.image.description="AEGIS, a defensive agentic security framework. Feature set of this image: ${AEGIS_FEATURES}." \
      org.opencontainers.image.source="https://github.com/onequbitaway/aegis" \
      org.opencontainers.image.licenses="MIT"

COPY --from=build /rootfs/ /

# The TLS clients read the trusted certificate authorities from this file.
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt

# A numeric user and group that are not root. The image has no /etc/passwd.
USER 65532:65532
WORKDIR /var/lib/aegis

# /etc/aegis      The configuration, the policy, the detection pack, and the playbooks.
# /var/lib/aegis  The audit log and the checkpoints of the sources.
# /plugins        The connector plugins.
VOLUME ["/etc/aegis", "/var/lib/aegis", "/plugins"]

# The image declares no port. The operator API of the full feature set listens on the
# address in `api.bind` of the configuration. The API has no TLS.

STOPSIGNAL SIGTERM
ENTRYPOINT ["/aegis"]
CMD ["run", "--config", "/etc/aegis/aegis.toml"]

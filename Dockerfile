# syntax=docker/dockerfile:1
#
# Builds every component of Aegis-eBPF. The Makefile drives these targets:
#
#   aegis-agent  runtime image of the control plane (Go)
#   aegis-probe  runtime image of the eBPF probe (Rust + Aya)
#   artifacts    both binaries, for `docker build --output`
#   go-test      gofmt, go vet and the Go tests
#   rust-test    rustfmt, clippy and the Rust tests

ARG GO_VERSION=1.27
ARG RUST_VERSION=1.98
# Nightly toolchain that compiles the eBPF programs, pinned for reproducible
# builds. It needs the rust-src component to build `core` for the BPF target.
ARG RUST_NIGHTLY=nightly-2026-09-23
# bpf-linker links the eBPF programs. Update the version and the checksums of
# its release archives together.
ARG BPF_LINKER_VERSION=0.11.1
ARG BPF_LINKER_SHA256_X86_64=e058a6aecc9e65fa4c977b298a8e4b738424d7629769fd352eed409fb57e16e8
ARG BPF_LINKER_SHA256_AARCH64=341ec1c595496877cae2b073544c2226d78a922739632b5732dbaa48507f1380

# --- Control plane (Go) ----------------------------------------------------

FROM golang:${GO_VERSION}-alpine AS go-src
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY api/ api/
COPY cmd/ cmd/
COPY internal/ internal/

FROM go-src AS go-test
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    unformatted="$(gofmt -l cmd internal)" \
 && if [ -n "$unformatted" ]; then echo "not gofmt-ed: $unformatted" >&2; exit 1; fi \
 && go vet ./... \
 && go test ./...

FROM go-src AS agent-build
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X main.version=${VERSION}" \
        -o /out/aegis-agent ./cmd/aegis-agent

FROM gcr.io/distroless/static-debian13:nonroot AS aegis-agent
COPY --from=agent-build /out/aegis-agent /usr/local/bin/aegis-agent
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/aegis-agent"]
# In a container, the API must listen on every interface to be reachable.
CMD ["-listen", ":8080"]

# --- eBPF probe (Rust) -----------------------------------------------------

FROM rust:${RUST_VERSION}-slim-trixie AS rust-src
ARG RUST_NIGHTLY
ARG BPF_LINKER_VERSION
ARG BPF_LINKER_SHA256_X86_64
ARG BPF_LINKER_SHA256_AARCH64
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl zstd \
 && rm -rf /var/lib/apt/lists/*
RUN rustup component add clippy \
 && rustup toolchain install "${RUST_NIGHTLY}" --profile minimal --component rust-src,rustfmt
# The release binaries of bpf-linker bundle LLVM.
RUN arch="$(uname -m)" \
 && case "$arch" in \
        x86_64) sum="${BPF_LINKER_SHA256_X86_64}" ;; \
        aarch64) sum="${BPF_LINKER_SHA256_AARCH64}" ;; \
        *) echo "no bpf-linker release for $arch" >&2; exit 1 ;; \
    esac \
 && curl -fsSLo /tmp/bpf-linker.tar.zst \
        "https://github.com/aya-rs/bpf-linker/releases/download/v${BPF_LINKER_VERSION}/bpf-linker-${arch}-unknown-linux-musl.tar.zst" \
 && echo "${sum}  /tmp/bpf-linker.tar.zst" | sha256sum -c - \
 && tar --zstd -xf /tmp/bpf-linker.tar.zst -C /usr/local/bin \
 && rm /tmp/bpf-linker.tar.zst \
 && bpf-linker --version
# Read by crates/aegis-probe/build.rs.
ENV AEGIS_EBPF_TOOLCHAIN=${RUST_NIGHTLY}
WORKDIR /src
COPY Cargo.toml Cargo.lock rustfmt.toml ./
COPY crates/ crates/

FROM rust-src AS rust-test
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo "+${AEGIS_EBPF_TOOLCHAIN}" fmt --all --check \
 && cargo clippy --locked --all-targets -- -D warnings \
 && cargo test --locked

FROM rust-src AS probe-build
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    --mount=type=cache,target=/src/target \
    cargo build --locked --release -p aegis-probe \
 && install -D target/release/aegis-probe /out/aegis-probe

# The probe loads eBPF programs: it runs as root, with privileges.
FROM gcr.io/distroless/cc-debian13 AS aegis-probe
COPY --from=probe-build /out/aegis-probe /usr/local/bin/aegis-probe
ENTRYPOINT ["/usr/local/bin/aegis-probe"]

# --- Binaries only -----------------------------------------------------------

FROM scratch AS artifacts
COPY --from=agent-build /out/aegis-agent /
COPY --from=probe-build /out/aegis-probe /

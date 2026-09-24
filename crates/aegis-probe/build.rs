use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;

/// Compiles the eBPF programs of `aegis-probe-ebpf` for the BPF target, so
/// that `main.rs` can embed them.
///
/// `AEGIS_EBPF_TOOLCHAIN` selects the nightly toolchain that compiles them,
/// e.g. `nightly-2026-09-23`; it defaults to `nightly`. Set `AYA_BUILD_SKIP=1`
/// to skip them when only building or testing the library.
fn main() -> anyhow::Result<()> {
    println!("cargo:rerun-if-env-changed=AEGIS_EBPF_TOOLCHAIN");
    let toolchain = std::env::var("AEGIS_EBPF_TOOLCHAIN").ok();
    let toolchain = toolchain
        .as_deref()
        .map_or(Toolchain::Nightly, Toolchain::Custom);

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name.as_str() == "aegis-probe-ebpf")
        .ok_or_else(|| anyhow!("aegis-probe-ebpf package not found"))?;
    let cargo_metadata::Package {
        name,
        manifest_path,
        ..
    } = ebpf_package;
    let ebpf_package = aya_build::Package {
        name: name.as_str(),
        root_dir: manifest_path
            .parent()
            .ok_or_else(|| anyhow!("no parent for {manifest_path}"))?
            .as_str(),
        ..Default::default()
    };
    aya_build::build_ebpf([ebpf_package], toolchain)
}

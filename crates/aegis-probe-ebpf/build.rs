use which::which;

/// Building this crate has an undeclared dependency on the `bpf-linker`
/// binary. Rebuild it whenever `bpf-linker` changes. See aya-template for the
/// limits of this approach.
fn main() {
    let bpf_linker = which("bpf-linker").unwrap();
    println!("cargo:rerun-if-changed={}", bpf_linker.to_str().unwrap());
}

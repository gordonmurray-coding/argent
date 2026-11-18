//! The RISC Zero verify builtins pass through Argent to Silverscript 1.0.1 under
//! Argent-legal names: `r0_g16_verify` → `r0.g16.verify`, `r0_succinct_verify` →
//! `r0.succinct.verify` (7 arguments: claim, control_index, control_digests, seal, journal, image_id,
//! control_id). Silverscript types them (both are void).
use std::{fs, path::PathBuf};

fn build(name: &str, source: &str) -> argent::Result<argent::artifact::Artifact> {
    let out_dir = std::env::temp_dir().join(format!("argent-zk-builtins-{name}-{}", std::process::id()));
    let result = argent::build_inline(PathBuf::from(format!("{name}.ag")), source.to_string(), &out_dir);
    if out_dir.exists() {
        fs::remove_dir_all(&out_dir).expect("test output is removed");
    }
    result
}

const G16: &str = r#"
state S { int n; }
actor A owns S {
    entry check(byte[32] j, byte[] p, byte[32] img) emits next: A {
        r0_g16_verify(j, p, img);
        require(next.value == self.value);
        become next <- A(S { n: n });
    }
}
app ZkApp { actor A; }
"#;

#[test]
fn r0_g16_verify_passes_through_and_compiles() {
    build("g16", G16).unwrap_or_else(|err| panic!("r0_g16_verify should pass through to Silverscript: {err}"));
}

#[test]
fn r0_g16_verify_wrong_arity_is_typed_by_silverscript_under_its_real_name() {
    let source = G16.replace("r0_g16_verify(j, p, img)", "r0_g16_verify(j, p)");
    let err = match build("g16-arity", &source) {
        Ok(_) => panic!("two arguments must not compile"),
        Err(err) => err.to_string(),
    };
    assert!(err.contains("r0.g16.verify"), "Silverscript should report the dotted builtin name: {err}");
}

#[test]
fn r0_succinct_verify_passes_through_and_compiles() {
    let source = r#"
state S { int n; }
actor A owns S {
    entry check(byte[32] claim, byte[4] idx, byte[] digests, byte[] seal, byte[32] journal, byte[32] img, byte[32] control_id) emits next: A {
        r0_succinct_verify(claim, idx, digests, seal, journal, img, control_id);
        require(next.value == self.value);
        become next <- A(S { n: n });
    }
}
app ZkApp { actor A; }
"#;
    build("succinct", source).unwrap_or_else(|err| panic!("r0_succinct_verify should pass through to Silverscript: {err}"));
}

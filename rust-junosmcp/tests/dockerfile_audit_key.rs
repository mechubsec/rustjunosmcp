//! The container image must not ship unkeyed audit by omission (mecmcp#376 /
//! MEC-978): five of six server images ran with no `--audit-hmac-key-file`
//! in ENTRYPOINT while every systemd unit keyed it. CMD is operator-replaced
//! on every `docker run` with extra arguments, so the flag must live in
//! ENTRYPOINT, not CMD, to survive that.

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

#[test]
fn the_entrypoint_pre_provisions_an_audit_hmac_key() {
    let text = std::fs::read_to_string(repo_root().join("Dockerfile")).expect("read Dockerfile");
    let entrypoint_start = text
        .find("ENTRYPOINT [")
        .expect("Dockerfile has an ENTRYPOINT instruction");
    let entrypoint_end = text[entrypoint_start..]
        .find(']')
        .map(|offset| entrypoint_start + offset)
        .expect("ENTRYPOINT instruction is closed");
    let entrypoint = &text[entrypoint_start..entrypoint_end];

    assert!(
        entrypoint.contains("--audit-hmac-key-file"),
        "ENTRYPOINT must carry --audit-hmac-key-file so the image generates a \
         keyed audit HMAC key on first run instead of shipping unkeyed by \
         omission, got: {entrypoint}"
    );
}

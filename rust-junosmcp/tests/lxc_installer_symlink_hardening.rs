//! `packaging/lxc/install.sh` provisions `tokens.json` and `audit-hmac.key`
//! under the service's own state directory on first install. The installer
//! must refuse a non-regular path at either location and install generated
//! content with a fixed owner and mode, rather than writing or chmod/chown
//! through whatever is already there.

fn repo_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn install_sh() -> String {
    std::fs::read_to_string(repo_root().join("packaging/lxc/install.sh")).expect("read install.sh")
}

#[test]
fn the_lxc_installer_refuses_a_non_regular_tokens_file_path() {
    let text = install_sh();
    assert!(
        text.contains("-L \"$state_tokens_file\""),
        "install.sh must refuse a non-regular tokens.json path before \
         touching it, got: {text}"
    );
}

#[test]
fn the_lxc_installer_installs_the_tokens_file_with_a_fixed_owner_and_mode() {
    let text = install_sh();
    let tokens_block_start = text
        .find("state_tokens_file=\"$STATE_DIR/tokens.json\"")
        .expect("install.sh declares state_tokens_file");
    let tokens_block_end = text[tokens_block_start..]
        .find("audit_key=\"$STATE_DIR/audit-hmac.key\"")
        .expect("tokens block precedes the audit-hmac-key block");
    let tokens_block = &text[tokens_block_start..tokens_block_start + tokens_block_end];

    assert!(
        tokens_block.contains("install -m 0600 -o \"$SERVICE_USER\" -g \"$SERVICE_GROUP\""),
        "tokens.json must be provisioned with install(1) at a fixed owner \
         and mode, got: {tokens_block}"
    );
    assert!(
        !tokens_block.contains("> \"$state_tokens_file\""),
        "tokens.json must be provisioned with install(1), not a direct \
         redirect, got: {tokens_block}"
    );
    assert!(
        !tokens_block.contains("chown")
            && !tokens_block.contains("chmod 0600 \"$state_tokens_file\""),
        "tokens.json's owner and mode must come from install(1), not a \
         separate chown/chmod, got: {tokens_block}"
    );
}

#[test]
fn the_lxc_installer_refuses_a_non_regular_audit_hmac_key_path() {
    let text = install_sh();
    assert!(
        text.contains("-L \"$audit_key\""),
        "install.sh must refuse a non-regular audit-hmac.key path before \
         touching it, got: {text}"
    );
}

#[test]
fn the_lxc_installer_installs_the_audit_hmac_key_with_a_fixed_owner_and_mode() {
    let text = install_sh();
    let audit_key_block_start = text
        .find("audit_key=\"$STATE_DIR/audit-hmac.key\"")
        .expect("install.sh declares audit_key");
    let audit_key_block = &text[audit_key_block_start..];

    assert!(
        audit_key_block.contains("install -m 0600 -o \"$SERVICE_USER\" -g \"$SERVICE_GROUP\" \"$audit_key_tmp\" \"$audit_key\""),
        "the generated key must be installed with a fixed owner and mode, \
         got: {audit_key_block}"
    );
    assert!(
        !audit_key_block.contains(">\"$audit_key\"")
            && !audit_key_block.contains("> \"$audit_key\""),
        "audit-hmac.key must be provisioned with install(1), not a direct \
         redirect, got: {audit_key_block}"
    );
}

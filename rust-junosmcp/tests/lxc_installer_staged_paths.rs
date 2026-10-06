#![allow(clippy::unwrap_used)]
#![allow(missing_docs)]
//! Behavioural coverage for `packaging/lxc/install.sh`'s state-file
//! provisioning. The installer must refuse to continue when a path it is
//! about to create, chmod, or chown is not a plain file (or directory), and
//! it must leave whatever that path currently points at untouched rather
//! than writing or re-owning through it.
//!
//! This runs the real installer twice in a staged root
//! (`JMCP_INSTALL_ROOT`, `JMCP_INSTALL_SKIP_USER=1`): once to produce a
//! normal first install, then a second time after replacing one of its
//! state files with a stand-in pointing outside the staged root, which is
//! the shape an upgrade run would see.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

/// Build a minimal fake release package next to a copy of the real
/// `install.sh`, matching the layout `scripts/package-lxc.sh` produces.
fn build_fake_package(pkg_root: &Path) {
    fs::create_dir_all(pkg_root.join("usr/local/bin")).unwrap();
    fs::create_dir_all(pkg_root.join("etc/jmcp")).unwrap();
    fs::create_dir_all(pkg_root.join("etc/systemd/system")).unwrap();

    let bin = pkg_root.join("usr/local/bin/rust-junosmcp");
    fs::write(&bin, "#!/bin/sh\nexit 0\n").unwrap();
    let mut perms = fs::metadata(&bin).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(&bin, perms).unwrap();

    fs::write(pkg_root.join("etc/jmcp/devices.json.example"), "{}\n").unwrap();
    fs::write(
        pkg_root.join("etc/systemd/system/rust-junosmcp.service"),
        "[Unit]\nDescription=stub\n",
    )
    .unwrap();

    let real_install_sh = repo_root().join("packaging/lxc/install.sh");
    let staged_install_sh = pkg_root.join("install.sh");
    fs::copy(&real_install_sh, &staged_install_sh).unwrap();
    let mut perms = fs::metadata(&staged_install_sh).unwrap().permissions();
    std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
    fs::set_permissions(&staged_install_sh, perms).unwrap();
}

fn run_install(pkg_root: &Path, install_root: &Path) -> std::process::Output {
    Command::new("bash")
        .arg(pkg_root.join("install.sh"))
        .env("JMCP_INSTALL_ROOT", install_root)
        .env("JMCP_INSTALL_SKIP_USER", "1")
        .env("JMCP_INSTALL_SKIP_SYSTEMD_RELOAD", "1")
        .env("JMCP_INSTALL_SKIP_RUNTIME_DEPS", "1")
        .output()
        .expect("run install.sh")
}

struct StagedInstall {
    _pkg_dir: tempfile::TempDir,
    pkg_root: PathBuf,
    install_root: tempfile::TempDir,
}

impl StagedInstall {
    fn new() -> Self {
        let pkg_dir = tempfile::tempdir().unwrap();
        let pkg_root = pkg_dir.path().join("pkg");
        build_fake_package(&pkg_root);
        let install_root = tempfile::tempdir().unwrap();
        Self {
            _pkg_dir: pkg_dir,
            pkg_root,
            install_root,
        }
    }

    fn run(&self) -> std::process::Output {
        run_install(&self.pkg_root, self.install_root.path())
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.install_root.path().join(relative)
    }
}

#[test]
fn a_fresh_install_creates_plain_state_files_with_the_right_mode() {
    let staged = StagedInstall::new();
    let output = staged.run();
    assert!(
        output.status.success(),
        "first install must succeed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    for (relative, expected_mode) in [
        ("var/lib/jmcp/tokens.json", 0o600),
        ("etc/jmcp/known_hosts", 0o644),
        ("var/lib/jmcp/changeset-state.json", 0o600),
        ("var/lib/jmcp/audit-hmac.key", 0o600),
    ] {
        let path = staged.path(relative);
        let meta = fs::symlink_metadata(&path).unwrap_or_else(|e| {
            panic!("{relative} must exist after a fresh install: {e}")
        });
        assert!(
            meta.file_type().is_file(),
            "{relative} must be a plain file, got {:?}",
            meta.file_type()
        );
        let mode = std::os::unix::fs::PermissionsExt::mode(&meta.permissions()) & 0o777;
        assert_eq!(mode, expected_mode, "{relative} has unexpected mode");
    }
}

/// Re-run the installer after something other than a plain file has taken
/// the place of one of its state paths, the way an upgrade run would see it.
/// The installer must refuse rather than write or re-own through it, and
/// whatever that path points at outside the staged root must stay untouched.
fn assert_second_install_refuses_a_hijacked_path(relative: &str) {
    let staged = StagedInstall::new();
    let first = staged.run();
    assert!(
        first.status.success(),
        "first install must succeed before the attack scenario: {}",
        String::from_utf8_lossy(&first.stderr)
    );

    let canary_dir = tempfile::tempdir().unwrap();
    let canary = canary_dir.path().join("canary");
    fs::write(&canary, b"untouched").unwrap();

    let target = staged.path(relative);
    fs::remove_file(&target).unwrap();
    symlink(&canary, &target).unwrap();

    let second = staged.run();
    assert!(
        !second.status.success(),
        "install must refuse to continue once {relative} is not a plain file, stderr: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let canary_contents = fs::read(&canary).unwrap();
    assert_eq!(
        canary_contents, b"untouched",
        "{relative} pointed at {canary:?}; the installer must never write \
         through it"
    );
}

#[test]
fn second_install_refuses_a_hijacked_tokens_file() {
    assert_second_install_refuses_a_hijacked_path("var/lib/jmcp/tokens.json");
}

#[test]
fn second_install_refuses_a_hijacked_known_hosts_file() {
    assert_second_install_refuses_a_hijacked_path("etc/jmcp/known_hosts");
}

#[test]
fn second_install_refuses_a_hijacked_changeset_state_file() {
    assert_second_install_refuses_a_hijacked_path("var/lib/jmcp/changeset-state.json");
}

#[test]
fn second_install_refuses_a_hijacked_audit_hmac_key() {
    assert_second_install_refuses_a_hijacked_path("var/lib/jmcp/audit-hmac.key");
}

#[test]
fn second_install_refuses_a_hijacked_devices_file() {
    let staged = StagedInstall::new();
    let first = staged.run();
    assert!(first.status.success(), "first install must succeed");

    // devices.json is never created by the installer itself; simulate the
    // operator having copied the example in before the next upgrade run.
    let devices = staged.path("etc/jmcp/devices.json");
    fs::write(&devices, "{}\n").unwrap();
    let second = staged.run();
    assert!(
        second.status.success(),
        "a plain devices.json must not block an upgrade: {}",
        String::from_utf8_lossy(&second.stderr)
    );

    let canary_dir = tempfile::tempdir().unwrap();
    let canary = canary_dir.path().join("canary");
    fs::write(&canary, b"untouched").unwrap();
    fs::remove_file(&devices).unwrap();
    symlink(&canary, &devices).unwrap();

    let third = staged.run();
    assert!(
        !third.status.success(),
        "install must refuse to continue once devices.json is not a plain \
         file, stderr: {}",
        String::from_utf8_lossy(&third.stderr)
    );
    assert_eq!(
        fs::read(&canary).unwrap(),
        b"untouched",
        "devices.json pointed at {canary:?}; the installer must never chmod/chown through it"
    );
}

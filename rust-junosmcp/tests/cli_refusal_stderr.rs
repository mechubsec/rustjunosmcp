//! Pins the operator-visible startup refusals against the shared fixtures.
//!
//! Every server in the family must print the same text for the same refusal.
//! The expected text comes from `mecmcp_runtime::cli_validate::testing`, not
//! from a local copy, so a drift in either direction fails here.

use mecmcp_runtime::cli_validate::testing::{expected_stderr, refusal_fixtures};
use std::process::Command;

#[test]
fn every_shared_refusal_reaches_stderr_verbatim() {
    for (args, refusal) in refusal_fixtures() {
        let output = Command::new(env!("CARGO_BIN_EXE_rust-junosmcp"))
            .args(&args)
            .output()
            .expect("spawn rust-junosmcp");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            !output.status.success(),
            "{args:?} must exit non-zero, stderr:\n{stderr}"
        );
        assert!(
            stderr.lines().any(|l| l == expected_stderr(&refusal)),
            "stderr drifted from the shared contract for {args:?}:\n{stderr}"
        );
    }
}

//! `discard_candidate` — discard uncommitted candidate config (rollback 0),
//! returning the candidate to the running config. Never changes the running
//! config. Operates lock-free on the shared candidate to recover a candidate
//! left dirty ("configuration database modified").

use crate::device_manager::DeviceManager;
use crate::error::JmcpError;
use crate::tools::DiscardCandidateArgs;
use crate::tools::candidate_transaction::{self, CandidateMode, CandidateRequest, CandidateResult};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

/// Discard uncommitted candidate configuration (rollback 0).
///
/// Resets the candidate to match the running config. Operates lock-free on the
/// shared candidate to recover a candidate left dirty ("configuration database
/// modified"). Never changes the running config. Returns `{success, message}`.
pub async fn handle(
    args: DiscardCandidateArgs,
    dm: Arc<DeviceManager>,
    allow_plane_owned_writes: bool,
) -> Result<Value, JmcpError> {
    handle_with_cancel(args, dm, allow_plane_owned_writes, CancellationToken::new()).await
}

/// Cancellable variant of `handle` for use in transport shutdown paths.
pub async fn handle_with_cancel(
    args: DiscardCandidateArgs,
    dm: Arc<DeviceManager>,
    allow_plane_owned_writes: bool,
    ct: CancellationToken,
) -> Result<Value, JmcpError> {
    // Confirm the router exists before connecting.
    let _ = dm.inventory().get(&args.device)?;
    let timeout_dur = Duration::from_secs(args.timeout);

    let (result, warning) = candidate_transaction::run(
        &dm,
        &args.device,
        CandidateRequest {
            payload: None,
            rollback_source: None,
            mode: CandidateMode::Discard,
            // Unused: no payload is loaded on the discard path.
            load_action: rustez::LoadAction::Merge,
            tool: "discard_candidate",
            allow_plane_owned_writes,
        },
        timeout_dur,
        &ct,
    )
    .await?;
    let CandidateResult::Discarded = result else {
        unreachable!("discard transaction returned the wrong result kind");
    };
    let mut response = json!({
        "success": true,
        "message": "candidate configuration discarded (rolled back to running)"
    });
    if let Some(warning) = warning {
        response["warning"] = json!(warning);
    }
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inventory::Inventory;
    use std::io::Write;

    fn inv_with(json: &str) -> Arc<Inventory> {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        f.write_all(json.as_bytes()).unwrap();
        Arc::new(Inventory::load(f.path()).unwrap())
    }

    #[tokio::test]
    async fn unknown_router_propagates_error() {
        let inv = inv_with(
            r#"{"r1":{"ip":"127.0.0.1","username":"u","auth":{"type":"password","password":"x"}}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            DiscardCandidateArgs {
                device: "nope".into(),
                timeout: 5,
            },
            dm,
            false,
        )
        .await;
        assert!(matches!(r, Err(JmcpError::UnknownRouter(_))));
    }

    #[tokio::test]
    async fn mist_device_is_refused_before_connect() {
        let inv = inv_with(
            r#"{"r1":{"ip":"203.0.113.1","port":1,"username":"u","auth":{"type":"password","password":"x"},"config_authority":"mist"}}"#,
        );
        let dm = Arc::new(DeviceManager::new(inv));
        let r = handle(
            DiscardCandidateArgs {
                device: "r1".into(),
                timeout: 5,
            },
            dm,
            false,
        )
        .await;
        match r {
            Err(e @ JmcpError::PlaneManagedConfig { .. }) => {
                assert_eq!(e.audit_kind(), "blocked");
            }
            other => panic!("expected PlaneManagedConfig, got {other:?}"),
        }
    }
}

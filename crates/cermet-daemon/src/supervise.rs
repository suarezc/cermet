//! Surface supervision.

use tokio::task::{JoinError, JoinHandle};

/// Await all surface tasks; return as soon as the first one completes, labelled with its join result.
pub async fn supervise_surfaces(
    agent: JoinHandle<()>,
    ctl: JoinHandle<()>,
    owner: JoinHandle<()>,
    git: JoinHandle<()>,
    githook: JoinHandle<()>,
) -> (&'static str, Result<(), JoinError>) {
    tokio::select! {
        r = agent => ("agent.sock", r),
        r = ctl => ("ctl.sock", r),
        r = owner => ("owner.sock", r),
        r = git => ("git.sock", r),
        r = githook => ("githook.sock", r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn returns_on_first_surface_death_not_waiting_for_the_survivor() {
        let dying = tokio::spawn(async {});
        let surviving = tokio::spawn(std::future::pending::<()>());
        let owner = tokio::spawn(std::future::pending::<()>());
        let (which, res) = tokio::time::timeout(
            Duration::from_secs(2),
            supervise_surfaces(
                dying,
                surviving,
                owner,
                tokio::spawn(std::future::pending::<()>()),
                tokio::spawn(std::future::pending::<()>()),
            ),
        )
        .await
        .expect("supervise must return on first surface death, not block on the survivor");
        assert_eq!(which, "agent.sock", "the surface that died is identified");
        assert!(res.is_ok(), "a clean (non-panic) return is reported as Ok");
    }
}

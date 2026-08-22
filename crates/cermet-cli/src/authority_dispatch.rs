//! Shared frontend dispatch for operator sentence-authority and CERMET.md commands.

use std::path::Path;
use std::sync::Arc;

use cermet_ctl_client::broker_client::CtlBrokerClient;
use cermet_ctl_client::presence::Presence;

use crate::reconciliation::{self, CtlReconciliationClient};
use crate::rule_cli::{run_allow, run_refresh, run_revoke, run_rules, VendoredRuleCatalog};
use crate::sentence_ctl::{CtlDocumentSyncObserver, CtlStagedClient, StagedSentenceCustody};
use crate::tty::Terminal;
use crate::{CliCommand, CliError, CliOutput};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorityCommandOutput {
    pub text: String,
    pub exit_code: u8,
}

impl From<reconciliation::ReconciliationOutput> for AuthorityCommandOutput {
    fn from(output: reconciliation::ReconciliationOutput) -> Self {
        Self {
            text: output.text,
            exit_code: output.exit_code,
        }
    }
}

impl From<CliOutput> for AuthorityCommandOutput {
    fn from(output: CliOutput) -> Self {
        Self {
            text: output.text,
            exit_code: if output.ok { 0 } else { 1 },
        }
    }
}

/// Dispatch one parsed authority command through the same adapters used by the `cermet` binary.
/// `None` means the command belongs to another frontend path.
pub fn dispatch_authority_command(
    client: &CtlBrokerClient,
    command: &CliCommand,
    cwd: &Path,
    terminal: &dyn Terminal,
    presence: Arc<dyn Presence>,
) -> Result<Option<AuthorityCommandOutput>, CliError> {
    let reconciliation = || CtlReconciliationClient::new(client.clone()).map_err(CliError::Refused);
    let custody = || {
        let staged = CtlStagedClient::new(client.clone())
            .map_err(|error| CliError::Refused(error.to_string()))?;
        let observer = CtlDocumentSyncObserver::new(client.clone(), cwd.to_path_buf())
            .ok()
            .map(Arc::new);
        let custody = StagedSentenceCustody::new(Box::new(staged), presence.clone());
        Ok::<_, CliError>(match observer {
            Some(observer) => custody.with_document_sync(observer),
            None => custody,
        })
    };

    let output = match command {
        CliCommand::Init => reconciliation::run_init(&reconciliation()?, cwd).into(),
        CliCommand::DocCheck { fix } => {
            reconciliation::run_check(&reconciliation()?, cwd, *fix).into()
        }
        CliCommand::Diff => reconciliation::run_diff(&reconciliation()?, cwd).into(),
        CliCommand::Status { as_json } => {
            reconciliation::run_status(&reconciliation()?, cwd, *as_json).into()
        }
        CliCommand::Export { replace_draft } => {
            reconciliation::run_export(&reconciliation()?, cwd, *replace_draft).into()
        }
        CliCommand::Apply {
            file,
            replace_live,
            recover,
        } => reconciliation::run_apply(
            &reconciliation()?,
            cwd,
            file.as_ref().map(Path::new),
            *replace_live,
            *recover,
            terminal,
            presence.as_ref(),
        )
        .into(),
        // `preset` reuses the corpus ceremony verbatim; the ONE difference is where the body
        // comes from — the daemon's profile table instead of a repository document.
        CliCommand::Preset(command) => {
            let client = reconciliation()?;
            match command {
                crate::preset::PresetCommand::List => {
                    // The live profile is the daemon's own read-time join — asked for here, so an
                    // unreachable daemon costs the listing its marker, never the listing.
                    let live = reconciliation::ReconciliationClient::authority_status(&client)
                        .ok()
                        .and_then(|status| status.profile);
                    crate::preset::run_preset_list(&client, live.as_deref()).into()
                }
                crate::preset::PresetCommand::Apply { name, recover } => {
                    crate::preset::run_preset_apply(
                        &client,
                        &client,
                        name,
                        *recover,
                        terminal,
                        presence.as_ref(),
                    )
                    .into()
                }
                crate::preset::PresetCommand::Export { name, path, force } => {
                    crate::preset::run_preset_export(
                        &client,
                        name,
                        &crate::preset::export_target(path.as_deref()),
                        *force,
                    )
                    .into()
                }
            }
        }
        CliCommand::Allow { rule, yes } => run_allow(
            &custody()?,
            terminal,
            &VendoredRuleCatalog,
            &cermet_lang::sets::VendoredSetResolver,
            rule,
            *yes,
        )?
        .into(),
        CliCommand::Rules => run_rules(&custody()?)?.into(),
        CliCommand::Revoke { number, yes } => {
            run_revoke(&custody()?, terminal, *number, *yes)?.into()
        }
        CliCommand::Refresh { number } => run_refresh(
            &custody()?,
            &cermet_lang::sets::VendoredSetResolver,
            *number,
        )?
        .into(),
        _ => return Ok(None),
    };
    Ok(Some(output))
}

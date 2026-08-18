//! Structural tests: the retired promotion/learning/report/operation surfaces no
//! longer parse. Verbs arrive vendored (no agent proposal), there is no aggregate report, no operation
//! learner, and no operator-facing session-report views — so every one of these commands is now an
//! unknown/incomplete parse.

use cermet_cli::parse;

fn argv(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|s| s.to_string()).collect()
}

#[test]
fn deleted_proposal_commands_no_longer_parse() {
    for cmd in [
        vec!["report"],
        vec!["propose"],
        vec!["session-list"],
        vec!["session-show", "sess_1"],
        vec!["operation-list"],
        vec!["operation-show", "op_1"],
        vec!["contracts"],
        vec!["contracts", "list"],
        vec!["contracts", "ratify", "id"],
        vec!["contracts", "reject", "id"],
        vec!["policy", "suggest"],
        vec!["policy", "propose"],
        vec!["profile", "propose", "name"],
    ] {
        assert!(
            parse(&argv(&cmd)).is_err(),
            "`cermet {}` must fail parsing (retired)",
            cmd.join(" ")
        );
    }
}

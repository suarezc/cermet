//! What the build graph still proves, and what one binary retired.
//!
//! RETIRED (ONE-BINARY consolidation): the final shipped executable no longer
//! excludes vault-opening code. It is a composition of `cermet-cli` and `cermet-daemon`, so
//! `cermet-core`/`cermet-broker-actor` are linked into the same file the operator CLI and the MCP
//! bridge run from. Code presence is not privilege — `execve` hands a process the credentials its
//! CALLER chose, not the file owner's, nothing installed is setuid or file-capable, and the daemon
//! bytes were already world-readable and world-executable before the merge. A T1-steered model, a
//! T2 accident, or a T3 peer uid that runs the daemon role gets a process with its OWN uid, which
//! the `0700` state dir, the owner-checked key material, and the peercred socket gates refuse.
//!
//! SURVIVING, and still proved here: the `cermet-cli` LIBRARY graph — the crate that owns the
//! operator CLI, the MCP bridge, and git's remote helper — reaches no vault-owning code. That is
//! what keeps those roles honest clients: they cannot open service state or key material, because
//! they have no code that could, and all broker authority stays in the daemon role's process.

use std::collections::{HashMap, HashSet, VecDeque};
use std::process::Command;

use serde_json::Value;

/// The `cermet-cli` library's own dependency graph reaches no vault-owning crate.
///
/// This is a claim about the CLIENT LIBRARY, not about the shipped executable: the composition
/// crate deliberately reaches `cermet-daemon` (see `the_composition_crate_deliberately_reaches_the_daemon`).
#[test]
fn cermet_cli_library_dependency_graph_is_keyless() {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("cermet-cli must live under the workspace crates directory");
    let rustc = Command::new(option_env!("RUSTC").unwrap_or("rustc"))
        .arg("-vV")
        .output()
        .expect("rustc -vV must run");
    assert!(rustc.status.success(), "rustc -vV must succeed");
    let host = String::from_utf8(rustc.stdout)
        .expect("rustc -vV output must be UTF-8")
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("rustc -vV must report a host")
        .to_string();
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--offline",
            "--filter-platform",
            &host,
        ])
        .current_dir(workspace)
        .output()
        .expect("cargo metadata must run");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );

    let metadata: Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata must emit JSON");
    let packages = metadata["packages"]
        .as_array()
        .expect("metadata packages must be an array");
    let names = packages
        .iter()
        .map(|package| {
            (
                package["id"].as_str().expect("package id").to_string(),
                package["name"].as_str().expect("package name").to_string(),
            )
        })
        .collect::<HashMap<_, _>>();
    let nodes = metadata["resolve"]["nodes"]
        .as_array()
        .expect("metadata resolve nodes must be an array")
        .iter()
        .map(|node| {
            (
                node["id"].as_str().expect("node id").to_string(),
                node["deps"].as_array().expect("node deps").clone(),
            )
        })
        .collect::<HashMap<_, _>>();
    let root = names
        .iter()
        .find_map(|(id, name)| (name == "cermet-cli").then(|| id.clone()))
        .expect("cermet-cli package must exist");

    let mut queue = VecDeque::from([(root.clone(), vec!["cermet-cli".to_string()])]);
    let mut seen = HashSet::from([root]);
    while let Some((package_id, path)) = queue.pop_front() {
        for dependency in nodes.get(&package_id).expect("resolved package node") {
            let is_normal = dependency["dep_kinds"]
                .as_array()
                .expect("dependency kinds")
                .iter()
                .any(|kind| kind["kind"].is_null());
            if !is_normal {
                continue;
            }

            let dependency_id = dependency["pkg"]
                .as_str()
                .expect("resolved dependency package id");
            let dependency_name = names.get(dependency_id).expect("dependency package name");
            let mut dependency_path = path.clone();
            dependency_path.push(dependency_name.clone());
            assert!(
                !matches!(
                    dependency_name.as_str(),
                    "cermet-core" | "cermet-broker-actor"
                ),
                "the cermet-cli LIBRARY graph reaches vault-owning code: {}",
                dependency_path.join(" -> ")
            );
            if seen.insert(dependency_id.to_string()) {
                queue.push_back((dependency_id.to_string(), dependency_path));
            }
        }
    }
}

/// Every workspace binary target, resolved for this host.
fn workspace_binary_targets() -> Vec<String> {
    let metadata = workspace_metadata();
    let workspace_members = metadata["workspace_members"]
        .as_array()
        .expect("workspace members must be an array")
        .iter()
        .map(|member| member.as_str().expect("workspace member id"))
        .collect::<HashSet<_>>();
    let mut bins = metadata["packages"]
        .as_array()
        .expect("metadata packages must be an array")
        .iter()
        .filter(|package| {
            workspace_members.contains(package["id"].as_str().expect("package id must be a string"))
        })
        .flat_map(|package| {
            package["targets"]
                .as_array()
                .expect("package targets must be an array")
        })
        .filter(|target| {
            target["kind"]
                .as_array()
                .expect("target kinds must be an array")
                .iter()
                .any(|kind| kind.as_str() == Some("bin"))
        })
        .map(|target| {
            target["name"]
                .as_str()
                .expect("binary target name")
                .to_string()
        })
        .collect::<Vec<_>>();
    bins.sort();
    bins
}

/// ONE-BINARY: the workspace ships exactly one executable, named `cermet`.
///
/// `cermetd` and `git-remote-cermet` are not build targets any more — they are root-created
/// relative symlinks to this one file, and the role each name selects is decided by the composition
/// crate's closed dispatch table. A second bin target reappearing here means the merge regressed
/// and setup/packaging would silently go back to publishing separate, independently-skewable files.
#[test]
fn the_workspace_ships_exactly_one_cermet_bin() {
    assert_eq!(workspace_binary_targets(), ["cermet"]);
}

/// The other half of the retired invariant, stated as a test rather than left implicit: the
/// COMPOSITION crate reaches `cermet-daemon` on purpose. Reading this test next to
/// `cermet_cli_library_dependency_graph_is_keyless` is the whole boundary — the client library is
/// keyless, the shipped file is not, and what separates the roles at runtime is the uid the process
/// was launched with, never the bytes the file happens to contain.
#[test]
fn the_composition_crate_deliberately_reaches_the_daemon() {
    let metadata = workspace_metadata();
    let names = metadata["packages"]
        .as_array()
        .expect("metadata packages must be an array")
        .iter()
        .map(|package| {
            (
                package["id"].as_str().expect("package id").to_string(),
                package["name"].as_str().expect("package name").to_string(),
            )
        })
        .collect::<HashMap<_, _>>();
    let composition = names
        .iter()
        .find_map(|(id, name)| (name == "cermet-bin").then(|| id.clone()))
        .expect("the composition crate cermet-bin must exist");
    let direct = metadata["resolve"]["nodes"]
        .as_array()
        .expect("metadata resolve nodes must be an array")
        .iter()
        .find(|node| node["id"].as_str() == Some(composition.as_str()))
        .expect("resolved composition node")["deps"]
        .as_array()
        .expect("node deps")
        .iter()
        .filter_map(|dependency| names.get(dependency["pkg"].as_str()?).cloned())
        .collect::<HashSet<_>>();
    assert!(
        direct.contains("cermet-daemon") && direct.contains("cermet-cli"),
        "the sole bin composes both role libraries: {direct:?}"
    );
}

/// `cargo metadata` for this workspace, filtered to the host platform.
fn workspace_metadata() -> Value {
    let workspace = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(std::path::Path::parent)
        .expect("cermet-cli must live under the workspace crates directory");
    let rustc = Command::new(option_env!("RUSTC").unwrap_or("rustc"))
        .arg("-vV")
        .output()
        .expect("rustc -vV must run");
    assert!(rustc.status.success(), "rustc -vV must succeed");
    let host = String::from_utf8(rustc.stdout)
        .expect("rustc -vV output must be UTF-8")
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .expect("rustc -vV must report a host")
        .to_string();
    let output = Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--locked",
            "--offline",
            "--filter-platform",
            &host,
        ])
        .current_dir(workspace)
        .output()
        .expect("cargo metadata must run");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata must emit JSON")
}

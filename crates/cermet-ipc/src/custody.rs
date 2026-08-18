//! The declared custody ladder: which mechanism holds this box's vault key, and what that
//! mechanism honestly does and does not protect.
//!
//! Cermet takes the most secure path the box it is installed on can carry: when a TPM is
//! available it uses it, when a TPM isn't available but systemd credential delivery is it uses
//! that, when neither is available it takes the owner-only key file.
//!
//! Selection is AUTOMATIC — `cermet setup` walks this ladder top-down and takes the strongest rung
//! the box can actually carry — and DECLARED: the chosen rung is written to
//! `/etc/cermetd/config.toml` as `custody_profile`, printed in the setup summary, reported by
//! `cermet check`, and recorded in the audit chain. Descending is never silent, and the descent
//! prints the rung's own limitation in plain words.
//!
//! This type lives in the transport shim because BOTH sides need the same vocabulary from one
//! definition: `cermet setup` (which selects and records a profile) and `cermetd` (which dispatches
//! its key source on the declared one) are different binaries' roles with no other crate in common.

/// Which mechanism holds this box's vault key, strongest rung first.
///
/// The variants are not interchangeable implementations of one guarantee — each carries its OWN
/// assurance profile, which is why [`CustodyProfile::limitation`] exists and why nothing in the
/// codebase says "sealed" as though it were a single level. `systemd-creds` may bind a credential
/// to the TPM2 device, to the host secret at `/var/lib/systemd/credential.secret`, or to both; a
/// host-key-only blob is recoverable by anyone holding the whole host filesystem, because the
/// unseal key is ON that filesystem. Conflating the two would be a false claim, so `cermet setup`
/// asks for one EXPLICITLY (`--with-key=host+tpm2`, then `--with-key=host`) and records which
/// one answered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CustodyProfile {
    /// Hardware-bound: `systemd-creds encrypt --with-key=host+tpm2`. The encrypted vault key needs
    /// BOTH this OS installation's host secret and this box's TPM2 device, so a disk image alone
    /// does not yield it.
    #[serde(rename = "systemd-tpm2+host")]
    SystemdTpm2Host,
    /// Host-bound: `systemd-creds encrypt --with-key=host`. No Cermet-owned file carries the
    /// plaintext key, but systemd's host secret is an ordinary file on the same filesystem, so a
    /// full host image can carry both halves.
    SystemdHost,
    /// The `cermet`-owned `0600` `$CERMET_HOME/master.key`. Peer uids and unprivileged agents get a
    /// kernel `EACCES`; a copy of the filesystem gets the key.
    FileProtected,
}

impl CustodyProfile {
    /// The ladder `cermet setup` walks, strongest first. It takes the first rung the box can
    /// actually carry — provisioning is the probe.
    pub const LADDER: [CustodyProfile; 3] = [
        CustodyProfile::SystemdTpm2Host,
        CustodyProfile::SystemdHost,
        CustodyProfile::FileProtected,
    ];

    /// The declared spelling: the `custody_profile` config value, and the word every operator
    /// surface prints.
    pub fn as_str(self) -> &'static str {
        match self {
            CustodyProfile::SystemdTpm2Host => "systemd-tpm2+host",
            CustodyProfile::SystemdHost => "systemd-host",
            CustodyProfile::FileProtected => "file-protected",
        }
    }

    /// Parse a declared spelling. Fail-closed by construction: an unrecognized value is `None`, and
    /// every caller in service mode turns that into a refusal rather than a guess — a box whose
    /// config names a profile we do not implement must not fall back to a different key source,
    /// which would open the wrong vault (or none).
    pub fn parse(text: &str) -> Option<CustodyProfile> {
        CustodyProfile::LADDER
            .into_iter()
            .find(|profile| profile.as_str() == text)
    }

    /// What this rung honestly does NOT protect, in plain words. Printed verbatim by the setup
    /// summary and `cermet check` — this is the product's claim, so it is stated once, here, and
    /// never paraphrased at a call site.
    pub fn limitation(self) -> &'static str {
        match self {
            CustodyProfile::SystemdTpm2Host => {
                "encrypted vault key is bound to this OS installation and TPM2 device"
            }
            CustodyProfile::SystemdHost => {
                "persistent Cermet files do not contain the plaintext key; full host-image \
                 disclosure may permit recovery"
            }
            CustodyProfile::FileProtected => {
                "does not protect vault key from: disk snapshots or backups"
            }
        }
    }

    /// Does this rung receive its key through systemd's credential delivery
    /// (`LoadCredentialEncrypted=`), rather than from a file the daemon opens itself? The daemon's
    /// key-source dispatch and the credential-transport preflight both turn on this one question.
    pub fn is_systemd_credential(self) -> bool {
        match self {
            CustodyProfile::SystemdTpm2Host | CustodyProfile::SystemdHost => true,
            CustodyProfile::FileProtected => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::CustodyProfile;

    /// The wire vocabulary is a contract between `cermet setup` (writes it into config.toml) and
    /// `cermetd` (dispatches its key source on it). Pin the exact spellings.
    #[test]
    fn each_profile_round_trips_its_declared_spelling() {
        for (profile, spelling) in [
            (CustodyProfile::SystemdTpm2Host, "systemd-tpm2+host"),
            (CustodyProfile::SystemdHost, "systemd-host"),
            (CustodyProfile::FileProtected, "file-protected"),
        ] {
            assert_eq!(profile.as_str(), spelling);
            assert_eq!(CustodyProfile::parse(spelling), Some(profile));
        }
        assert_eq!(CustodyProfile::parse("uid-file"), None);
        assert_eq!(CustodyProfile::parse(""), None);
    }

    /// The ladder is ordered, strongest first, and `setup` walks it in that order.
    #[test]
    fn the_ladder_is_ordered_strongest_first() {
        assert_eq!(
            CustodyProfile::LADDER,
            [
                CustodyProfile::SystemdTpm2Host,
                CustodyProfile::SystemdHost,
                CustodyProfile::FileProtected,
            ]
        );
    }

    /// Every rung states what it does NOT protect, in plain words. A profile whose limitation went
    /// missing would be a silent claim; a profile that claimed snapshot protection it does not have
    /// would be a false one.
    #[test]
    fn every_rung_states_its_honest_limitation() {
        assert_eq!(
            CustodyProfile::FileProtected.limitation(),
            "does not protect vault key from: disk snapshots or backups"
        );
        assert_eq!(
            CustodyProfile::SystemdHost.limitation(),
            "persistent Cermet files do not contain the plaintext key; full host-image disclosure \
             may permit recovery"
        );
        assert_eq!(
            CustodyProfile::SystemdTpm2Host.limitation(),
            "encrypted vault key is bound to this OS installation and TPM2 device"
        );
    }

    /// Only the sealed rungs receive their key through systemd's credential delivery; that is the
    /// single question the daemon's key-source dispatch and the preflight wiring both ask.
    #[test]
    fn only_the_sealed_rungs_are_credential_delivered() {
        assert!(CustodyProfile::SystemdTpm2Host.is_systemd_credential());
        assert!(CustodyProfile::SystemdHost.is_systemd_credential());
        assert!(!CustodyProfile::FileProtected.is_systemd_credential());
    }
}

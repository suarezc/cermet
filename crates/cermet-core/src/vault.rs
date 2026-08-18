//! Encrypted credential store (AES-256-GCM at rest, secrets zeroize on drop).

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use secrecy::Secret;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::types::SafeCredential;
use crate::util::now_rfc3339;

pub(crate) const CREDENTIAL_GENERATION_DOMAIN: &[u8] = b"cermet-credential-generation-v1\0";

pub struct Vault {
    conn: Connection,
    cipher: Aes256Gcm,
    #[cfg(test)]
    credential_reads: std::cell::Cell<usize>,
}

impl Vault {
    pub fn open(path: &str, key: &[u8; 32]) -> Result<Self> {
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS credentials (
                reference     TEXT PRIMARY KEY,
                provider      TEXT NOT NULL,
                account_label TEXT,
                nonce         BLOB NOT NULL,
                ciphertext    BLOB NOT NULL,
                created_at    TEXT NOT NULL,
                last_used_at  TEXT
             );",
        )?;
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        Ok(Self {
            conn,
            cipher,
            #[cfg(test)]
            credential_reads: std::cell::Cell::new(0),
        })
    }

    pub fn connect(
        &self,
        reference: &str,
        provider: &str,
        account_label: Option<&str>,
        token: &str,
    ) -> Result<SafeCredential> {
        let mut nonce = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce);
        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), token.as_bytes())
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let created_at = now_rfc3339();
        self.conn.execute(
            "INSERT INTO credentials (reference, provider, account_label, nonce, ciphertext, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(reference) DO UPDATE SET
                provider=excluded.provider, account_label=excluded.account_label,
                nonce=excluded.nonce, ciphertext=excluded.ciphertext,
                -- A rotated credential is a NEW token that has not been used yet, so its
                -- usage clock resets — matching the `last_used: None` this returns.
                last_used_at=NULL",
            params![reference, provider, account_label, nonce.to_vec(), ciphertext, created_at],
        )?;
        Ok(SafeCredential {
            reference: reference.into(),
            provider: provider.into(),
            account_label: account_label.map(Into::into),
            created_at,
            last_used: None,
        })
    }

    /// Decrypt a credential for internal use.
    pub fn open_secret(&self, reference: &str) -> Result<Secret<String>> {
        self.open_secret_row(reference).map(|(secret, _)| secret)
    }

    /// Decrypt one credential row and bind the returned opaque generation to those exact encrypted
    /// bytes. The provider check prevents a row relabel from becoming a credential for another
    /// adapter.
    pub fn open_secret_with_generation(
        &self,
        reference: &str,
        expected_provider: &str,
    ) -> Result<(Secret<String>, String)> {
        let (secret, generation, provider) = self.open_secret_row_with_provider(reference)?;
        if provider != expected_provider {
            return Err(Error::Integrity(format!(
                "credential {reference} is stored for a different provider"
            )));
        }
        Ok((secret, generation))
    }

    /// Compare the current encrypted row with a frozen generation without decrypting it.
    pub fn matches_generation(
        &self,
        reference: &str,
        expected_provider: &str,
        expected_generation: &str,
    ) -> Result<bool> {
        #[cfg(test)]
        self.credential_reads.set(self.credential_reads.get() + 1);
        let row = self
            .conn
            .query_row(
                "SELECT provider, nonce, ciphertext FROM credentials WHERE reference = ?1",
                params![reference],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        let Some((provider, nonce, ciphertext)) = row else {
            return Ok(false);
        };
        if provider != expected_provider {
            return Ok(false);
        }
        Ok(credential_generation(reference, &provider, &nonce, &ciphertext) == expected_generation)
    }

    /// Recheck generation and decrypt the SAME row. This is the post-claim secret-open primitive.
    pub fn open_secret_for_generation(
        &self,
        reference: &str,
        expected_provider: &str,
        expected_generation: &str,
    ) -> Result<Secret<String>> {
        #[cfg(test)]
        self.credential_reads.set(self.credential_reads.get() + 1);
        let row = self
            .conn
            .query_row(
                "SELECT provider, nonce, ciphertext FROM credentials WHERE reference = ?1",
                params![reference],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        let (provider, nonce, ciphertext) =
            row.ok_or_else(|| Error::NotFound(format!("credential {reference}")))?;
        let generation = credential_generation(reference, &provider, &nonce, &ciphertext);
        if provider != expected_provider || generation != expected_generation {
            return Err(Error::Integrity(format!(
                "credential {reference} generation changed"
            )));
        }
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext.as_ref())
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let token = String::from_utf8(plaintext).map_err(|e| Error::Crypto(e.to_string()))?;
        Ok(Secret::new(token))
    }

    fn open_secret_row(&self, reference: &str) -> Result<(Secret<String>, String)> {
        let (secret, generation, _) = self.open_secret_row_with_provider(reference)?;
        Ok((secret, generation))
    }

    fn open_secret_row_with_provider(
        &self,
        reference: &str,
    ) -> Result<(Secret<String>, String, String)> {
        #[cfg(test)]
        self.credential_reads.set(self.credential_reads.get() + 1);
        let row = self
            .conn
            .query_row(
                "SELECT provider, nonce, ciphertext FROM credentials WHERE reference = ?1",
                params![reference],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, Vec<u8>>(2)?,
                    ))
                },
            )
            .optional()?;
        let (provider, nonce, ct) =
            row.ok_or_else(|| Error::NotFound(format!("credential {reference}")))?;
        let generation = credential_generation(reference, &provider, &nonce, &ct);
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), ct.as_ref())
            .map_err(|e| Error::Crypto(e.to_string()))?;
        let token = String::from_utf8(plaintext).map_err(|e| Error::Crypto(e.to_string()))?;
        Ok((Secret::new(token), generation, provider))
    }

    pub fn touch(&self, reference: &str) -> Result<()> {
        self.conn.execute(
            "UPDATE credentials SET last_used_at = ?1 WHERE reference = ?2",
            params![now_rfc3339(), reference],
        )?;
        Ok(())
    }

    pub fn list(&self) -> Result<Vec<SafeCredential>> {
        let mut stmt = self.conn.prepare(
            "SELECT reference, provider, account_label, created_at, last_used_at FROM credentials ORDER BY provider, reference",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(SafeCredential {
                reference: r.get(0)?,
                provider: r.get(1)?,
                account_label: r.get(2)?,
                created_at: r.get(3)?,
                last_used: r.get(4)?,
            })
        })?;
        Ok(rows.collect::<std::result::Result<_, _>>()?)
    }

    /// Plaintext of every stored secret, used only to feed the redaction scrubber.
    pub(crate) fn all_secrets(&self) -> Result<Vec<String>> {
        #[cfg(test)]
        self.credential_reads.set(self.credential_reads.get() + 1);
        let mut stmt = self
            .conn
            .prepare("SELECT nonce, ciphertext FROM credentials")?;
        let rows = stmt.query_map([], |r| {
            Ok((r.get::<_, Vec<u8>>(0)?, r.get::<_, Vec<u8>>(1)?))
        })?;
        let mut out = Vec::new();
        for row in rows {
            let (nonce, ct) = row?;
            if let Ok(pt) = self.cipher.decrypt(Nonce::from_slice(&nonce), ct.as_ref()) {
                if let Ok(s) = String::from_utf8(pt) {
                    out.push(s);
                }
            }
        }
        Ok(out)
    }

    #[cfg(test)]
    pub(crate) fn reset_credential_reads(&self) {
        self.credential_reads.set(0);
    }

    #[cfg(test)]
    pub(crate) fn credential_reads(&self) -> usize {
        self.credential_reads.get()
    }
}

fn credential_generation(
    reference: &str,
    provider: &str,
    nonce: &[u8],
    ciphertext: &[u8],
) -> String {
    let mut hash = Sha256::new();
    hash.update(CREDENTIAL_GENERATION_DOMAIN);
    for field in [reference.as_bytes(), provider.as_bytes(), nonce, ciphertext] {
        hash.update(field);
    }
    format!("sha256:{}", crate::util::hex(&hash.finalize()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    #[test]
    fn moneypath_generation_is_derived_from_the_encrypted_row_and_rotation_invalidates_it() {
        let vault = Vault::open(":memory:", &[7u8; 32]).unwrap();
        vault
            .connect("cred_stripe", "stripe", None, "sk_test_first")
            .unwrap();
        let (secret, generation) = vault
            .open_secret_with_generation("cred_stripe", "stripe")
            .unwrap();
        assert_eq!(secret.expose_secret(), "sk_test_first");
        assert!(generation.starts_with("sha256:"));
        assert_eq!(generation.len(), 71);
        assert!(!generation.contains("sk_test_first"));
        assert!(vault
            .matches_generation("cred_stripe", "stripe", &generation)
            .unwrap());
        assert!(!vault
            .matches_generation("cred_stripe", "github", &generation)
            .unwrap());
        drop(secret);

        vault
            .connect("cred_stripe", "stripe", None, "sk_test_rotated")
            .unwrap();
        let (_, rotated_generation) = vault
            .open_secret_with_generation("cred_stripe", "stripe")
            .unwrap();
        assert_ne!(generation, rotated_generation);
        assert!(!vault
            .matches_generation("cred_stripe", "stripe", &generation)
            .unwrap());
        assert!(vault
            .open_secret_for_generation("cred_stripe", "stripe", &generation)
            .is_err());
        assert_eq!(
            vault
                .open_secret_for_generation("cred_stripe", "stripe", &rotated_generation)
                .unwrap()
                .expose_secret(),
            "sk_test_rotated"
        );
    }
}

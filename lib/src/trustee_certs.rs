// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use std::collections::BTreeMap;

/// Name of the ConfigMap describing the target state of nodes' certificates.
/// See docs/design/tls-updates.md.
pub const TRUSTEE_CERTS_CONFIG_MAP: &str = "trustee-certs";

const MACHINE_CERTS_KEY: &str = "machine_certs";
const REVOKED_CERTS_KEY: &str = "revoked_certs";
const WANT_CERT_KEY: &str = "want_cert";
const WANT_SINCE_KEY: &str = "want_since";

/// In-memory representation of the `trustee-certs` ConfigMap's `data`.
/// Certificates are PEM-encoded. See docs/design/tls-updates.md.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct TrusteeCerts {
    /// Active certificates, to be installed on machines.
    pub machine_certs: Vec<String>,
    /// Revoked certificates, to be removed from machines.
    pub revoked_certs: Vec<String>,
    /// The certificate the Trustee deployment should switch to, if any.
    pub want_cert: Option<String>,
    /// RFC3339 timestamp of when `want_cert` was last updated.
    pub want_since: Option<String>,
}

impl TrusteeCerts {
    pub fn to_config_map_data(&self) -> BTreeMap<String, String> {
        let mut data = BTreeMap::from([
            (
                MACHINE_CERTS_KEY.to_string(),
                serde_json::to_string(&self.machine_certs).unwrap(),
            ),
            (
                REVOKED_CERTS_KEY.to_string(),
                serde_json::to_string(&self.revoked_certs).unwrap(),
            ),
        ]);
        if let Some(want_cert) = &self.want_cert {
            data.insert(WANT_CERT_KEY.to_string(), want_cert.clone());
        }
        if let Some(want_since) = &self.want_since {
            data.insert(WANT_SINCE_KEY.to_string(), want_since.clone());
        }
        data
    }

    pub fn from_config_map_data(data: &BTreeMap<String, String>) -> Result<Self> {
        let cert_list = |key: &str| -> Result<Vec<String>> {
            data.get(key)
                .map(|json| {
                    serde_json::from_str(json)
                        .with_context(|| format!("{key} is not a JSON array of strings"))
                })
                .transpose()
                .map(Option::unwrap_or_default)
        };
        Ok(Self {
            machine_certs: cert_list(MACHINE_CERTS_KEY)?,
            revoked_certs: cert_list(REVOKED_CERTS_KEY)?,
            want_cert: data.get(WANT_CERT_KEY).cloned(),
            want_since: data.get(WANT_SINCE_KEY).cloned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        let certs = TrusteeCerts {
            machine_certs: vec!["cert-a".to_string(), "cert-b".to_string()],
            revoked_certs: vec!["cert-old".to_string()],
            want_cert: Some("cert-b".to_string()),
            want_since: Some("2026-11-05T00:00:00Z".to_string()),
        };
        let data = certs.to_config_map_data();
        assert_eq!(TrusteeCerts::from_config_map_data(&data).unwrap(), certs);
    }

    #[test]
    fn empty_data_defaults() {
        let certs = TrusteeCerts::from_config_map_data(&BTreeMap::new()).unwrap();
        assert_eq!(certs, TrusteeCerts::default());
    }

    #[test]
    fn malformed_cert_list_errors() {
        let data = BTreeMap::from([(MACHINE_CERTS_KEY.to_string(), "not json".to_string())]);
        assert!(TrusteeCerts::from_config_map_data(&data).is_err());
    }
}

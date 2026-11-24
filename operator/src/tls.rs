// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use operator::TLS_DIR;

/// Returns the four command-line arguments that point a registration server to
/// the certificate and key in the TLS mount.
pub fn registration_tls_args() -> [String; 4] {
    [
        "--cert-path".to_string(),
        format!("{TLS_DIR}/tls.crt"),
        "--key-path".to_string(),
        format!("{TLS_DIR}/tls.key"),
    ]
}

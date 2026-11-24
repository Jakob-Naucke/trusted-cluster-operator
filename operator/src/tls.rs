// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use k8s_openapi::api::core::v1::{SecretVolumeSource, Volume, VolumeMount};
use operator::TLS_DIR;

/// Returns a volume referencing `secret_name` and a matching mount
/// at `TLS_DIR` for a serving container.
pub fn tls_volume(secret_name: &str) -> (Volume, VolumeMount) {
    let name = secret_name.to_string();
    let volume = Volume {
        name: name.clone(),
        secret: Some(SecretVolumeSource {
            secret_name: Some(secret_name.to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };
    let mount = VolumeMount {
        name,
        mount_path: TLS_DIR.to_string(),
        ..Default::default()
    };
    (volume, mount)
}

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

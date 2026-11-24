// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, ensure};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{Secret, SecretVolumeSource, Volume, VolumeMount};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use kube::api::{Patch, PatchParams};
use kube::{Api, Client, ResourceExt};
use operator::{TLS_DIR, generate_owner_reference};
use serde_json::json;
use trusted_cluster_operator_lib::{TrustedExecutionCluster, endpoints::TRUSTEE_DEPLOYMENT};

pub const MANAGED_TRUSTEE_TLS: &str = "trustee-serving-tls";
const TLS_SOURCE: &str = "trusted-execution-clusters.io/tls-source-secret";

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

/// Finds any container's TLS mount in a Deployment. Returns the backing
/// volume and mount, `None` when the container has no TLS mount, or an error
/// when the pod spec, container, or backing volume is missing.
pub fn tls_mount(deployment: &Deployment) -> Result<Option<(&Volume, &VolumeMount)>> {
    let pod = deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.template.spec.as_ref())
        .context("Deployment has no pod spec")?;
    let Some(mount) = pod
        .containers
        .iter()
        .flat_map(|c| c.volume_mounts.as_ref())
        .flatten()
        .find(|vm| vm.mount_path == TLS_DIR)
    else {
        return Ok(None);
    };
    let volume = pod
        .volumes
        .iter()
        .flatten()
        .find(|volume| volume.name == mount.name)
        .context("TLS volume mount has no matching volume")?;
    Ok(Some((volume, mount)))
}

/// Returns the Secret name referenced by a TLS volume so callers can identify
/// its credential source. Returns an error if the reference is missing.
pub fn mounted_secret(volume: &Volume) -> Result<&str> {
    volume
        .secret
        .as_ref()
        .and_then(|secret| secret.secret_name.as_deref())
        .context("TLS volume has no Secret name")
}

/// Returns the non-empty bytes stored under `key` in a TLS Secret for callers
/// that need certificate data. Reports a missing or empty entry.
fn secret_entry<'a>(secret: &'a Secret, key: &str) -> Result<&'a [u8]> {
    secret
        .data
        .as_ref()
        .and_then(|data| data.get(key))
        .map(|bytes| bytes.0.as_slice())
        .filter(|bytes| !bytes.is_empty())
        .with_context(|| format!("TLS Secret {} has no {key}", secret.name_any()))
}

/// Returns the Trustee Secret's `ca.crt` as UTF-8 for publication to Machines.
/// Returns an error when the entry is missing, empty, or invalid UTF-8.
pub fn trustee_ca(secret: &Secret) -> Result<&str> {
    std::str::from_utf8(secret_entry(secret, "ca.crt")?)
        .context("Trustee CA certificate is not UTF-8")
}

/// Returns whether the resource metadata contains an owner reference matching
/// the supplied owner's UID. This scopes credentials and Machines to the TEC.
fn owned_by(meta: &ObjectMeta, owner: &OwnerReference) -> bool {
    meta.owner_references
        .iter()
        .flatten()
        .any(|reference| reference.uid == owner.uid)
}

/// Returns the operator-managed Trustee Secret with the source Secret's data
/// and name recorded and the TEC set as owner. Pass an existing managed Secret
/// to retain its metadata for replacement, or a default Secret for creation.
fn managed_secret(mut managed: Secret, source: &Secret, owner: &OwnerReference) -> Secret {
    managed.metadata.name = Some(MANAGED_TRUSTEE_TLS.to_string());
    managed.metadata.owner_references = Some(vec![owner.clone()]);
    managed
        .metadata
        .annotations
        .get_or_insert_with(Default::default)
        .insert(TLS_SOURCE.to_string(), source.name_any());
    managed.data.clone_from(&source.data);
    managed.type_ = Some("kubernetes.io/tls".to_string());
    managed
}

/// Returns the TEC's managed Trustee Secret from the client's default namespace.
/// If absent, creates it from the Secret mounted by the legacy Deployment or,
/// before deployment, from the configured Secret name. Reusing the existing copy
/// preserves the serving credentials while a new CA is staged.
pub async fn ensure_trustee_secret(
    client: &Client,
    configured: &str,
    deployment: Option<&Deployment>,
    owner: &OwnerReference,
) -> Result<Secret> {
    ensure!(
        configured != MANAGED_TRUSTEE_TLS,
        "{MANAGED_TRUSTEE_TLS} is reserved for the operator's Trustee TLS Secret"
    );
    let secrets: Api<Secret> = Api::default_namespaced(client.clone());
    if let Some(managed) = secrets.get_opt(MANAGED_TRUSTEE_TLS).await? {
        ensure!(
            owned_by(&managed.metadata, owner),
            "{MANAGED_TRUSTEE_TLS} already exists without this TEC as its owner"
        );
        return Ok(managed);
    }

    let source_name = match deployment {
        Some(deployment) => {
            let (volume, _) =
                tls_mount(deployment)?.context("Existing Trustee Deployment has no TLS mount")?;
            let name = mounted_secret(volume)?;
            ensure!(
                name != MANAGED_TRUSTEE_TLS,
                "Trustee's mounted {MANAGED_TRUSTEE_TLS} Secret is missing"
            );
            name
        }
        None => configured,
    };
    let source = secrets.get(source_name).await?;
    Ok(secrets
        .create(
            &Default::default(),
            &managed_secret(Secret::default(), &source, owner),
        )
        .await?)
}

async fn switch_to_managed_secret(
    deployments: &Api<Deployment>,
    deployment: &Deployment,
    volume: &Volume,
) -> Result<()> {
    let mut managed_volume = volume.clone();
    managed_volume
        .secret
        .as_mut()
        .context("TLS volume has no Secret")?
        .secret_name = Some(MANAGED_TRUSTEE_TLS.to_string());
    deployments
        .patch(
            &deployment.name_any(),
            &PatchParams::default(),
            &Patch::Strategic(json!({
                "metadata": { "resourceVersion": deployment.metadata.resource_version },
                "spec": { "template": { "spec": { "volumes": [managed_volume] } } }
            })),
        )
        .await?;
    Ok(())
}

/// Seeds the managed Secret from the currently mounted Secret and switches a
/// legacy Trustee Deployment to the copy without changing its TLS credentials.
pub async fn migrate_trustee_secret(
    client: &Client,
    cluster: &TrustedExecutionCluster,
) -> Result<()> {
    let Some(configured) = cluster.spec.trustee_secret.as_deref() else {
        return Ok(());
    };
    let deployments: Api<Deployment> = Api::default_namespaced(client.clone());
    let deployment = deployments.get(TRUSTEE_DEPLOYMENT).await?;
    let owner = generate_owner_reference(cluster)?;
    ensure_trustee_secret(client, configured, Some(&deployment), &owner).await?;
    let (volume, _) = tls_mount(&deployment)?.context("Trustee Deployment has no TLS mount")?;
    if mounted_secret(volume)? != MANAGED_TRUSTEE_TLS {
        switch_to_managed_secret(&deployments, &deployment, volume).await?;
    }
    Ok(())
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

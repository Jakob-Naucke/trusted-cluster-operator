// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::collections::BTreeMap;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use chrono::{DateTime, Utc};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{ConfigMap, Secret, SecretVolumeSource, Volume, VolumeMount};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Api, Client, ResourceExt};
use serde_json::json;
use trusted_cluster_operator_lib::{conditions::*, endpoints::*, trustee_certs::*, *};

use operator::{LONG_REQUEUE, TLS_DIR};

pub const MANAGED_TRUSTEE_TLS: &str = "trustee-serving-tls";
const TLS_SOURCE: &str = "trusted-execution-clusters.io/tls-source-secret";
const ROLLOUT_REQUEUE: Action = Action::requeue(Duration::from_secs(10));
const DEFAULT_GRACE_SECONDS: i32 = 86_400;

/// Returns a volume referencing `secret_name` and a matching read-only mount
/// at `TLS_DIR` for a serving container.
pub fn tls_volume(secret_name: &str) -> (Volume, VolumeMount) {
    let name = "serving-tls".to_string();
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
        read_only: Some(true),
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

/// Returns a hex-encoded SHA-256 revision for a Pod template from the source
/// Secret name, `tls.crt`, and optional `ca.crt`. Returns an error when the
/// serving certificate is missing or empty.
fn tls_revision(secret: &Secret, source_name: &str) -> Result<String> {
    let ca = secret
        .data
        .as_ref()
        .and_then(|data| data.get("ca.crt"))
        .map_or(&[][..], |bytes| bytes.0.as_slice());
    let mut hash = openssl::sha::Sha256::new();
    for value in [source_name.as_bytes(), secret_entry(secret, "tls.crt")?, ca] {
        hash.update(&(value.len() as u64).to_be_bytes());
        hash.update(value);
    }
    Ok(hex::encode(hash.finish()))
}

/// Returns the serving revision for the managed Trustee Secret, using the
/// original Secret name recorded in its source annotation. A missing source
/// annotation or serving certificate returns an error.
pub fn trustee_revision(secret: &Secret) -> Result<String> {
    let source = secret
        .annotations()
        .get(TLS_SOURCE)
        .context("Managed Trustee TLS Secret lacks its source annotation")?;
    tls_revision(secret, source)
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

/// Patches the Deployment through the supplied API with a TLS volume and revision
/// annotation. Uses the Deployment's resource version and returns success when
/// the API accepts the Pod template change that requests a rollout.
async fn patch_tls_template(
    deployments: &Api<Deployment>,
    deployment: &Deployment,
    volume: &Volume,
    revision: &str,
) -> Result<()> {
    let template = json!({
        "metadata": { "annotations": { TLS_REVISION: revision } },
        "spec": { "volumes": [volume] }
    });
    deployments
        .patch(
            &deployment.name_any(),
            &PatchParams::default(),
            &Patch::Strategic(json!({
                "metadata": { "resourceVersion": deployment.metadata.resource_version },
                "spec": { "template": template }
            })),
        )
        .await?;
    Ok(())
}

/// Returns the Deployment's Pod template TLS revision, if present, for comparison
/// with the desired revision.
fn deployed_revision(deployment: &Deployment) -> Option<&str> {
    deployment
        .spec
        .as_ref()?
        .template
        .metadata
        .as_ref()?
        .annotations
        .as_ref()?
        .get(TLS_REVISION)
        .map(String::as_str)
}

/// Reads the TEC-owned `trustee-certs` ConfigMap through the supplied API.
/// Returns the live object for subsequent writes and the decoded certificate
/// state. An absent ConfigMap yields `None` and empty state.
async fn get_certs(
    maps: &Api<ConfigMap>,
    owner: &OwnerReference,
) -> Result<(Option<ConfigMap>, TrusteeCerts)> {
    let map = maps.get_opt(TRUSTEE_CERTS_CONFIG_MAP).await?;
    let certs = match &map {
        Some(map) => {
            ensure!(
                owned_by(&map.metadata, owner),
                "trustee-certs is owned by another resource"
            );
            TrusteeCerts::from_config_map_data(map.data.as_ref().unwrap_or(&BTreeMap::new()))?
        }
        None => TrusteeCerts::default(),
    };
    Ok((map, certs))
}

/// Publishes the desired certificate state through the ConfigMap API. Replaces
/// the supplied live object if its data changed or creates one for the TEC owner
/// if absent. Returns success when the desired state is stored.
async fn save_certs(
    maps: &Api<ConfigMap>,
    map: Option<ConfigMap>,
    certs: &TrusteeCerts,
    owner: &OwnerReference,
) -> Result<()> {
    let data = Some(certs.to_config_map_data());
    if let Some(mut map) = map {
        if map.data != data {
            map.data = data;
            maps.replace(TRUSTEE_CERTS_CONFIG_MAP, &Default::default(), &map)
                .await?;
        }
    } else {
        let map = ConfigMap {
            metadata: ObjectMeta {
                name: Some(TRUSTEE_CERTS_CONFIG_MAP.to_string()),
                owner_references: Some(vec![owner.clone()]),
                ..Default::default()
            },
            data,
            ..Default::default()
        };
        maps.create(&Default::default(), &map).await?;
    }
    Ok(())
}

/// Updates the certificate state in place so the supplied CA is listed for
/// Machines to install and removed from the revoked list.
fn retain_cert(certs: &mut TrusteeCerts, ca: &str) {
    if !certs.machine_certs.iter().any(|cert| cert == ca) {
        certs.machine_certs.push(ca.to_string());
    }
    certs.revoked_certs.retain(|cert| cert != ca);
}

/// Keeps the active and desired CAs in the Machine certificate state during
/// staging. Records `now` when the desired CA changes and returns the remaining
/// grace time using `grace_seconds`, or zero if the deadline has passed.
fn stage_ca(
    certs: &mut TrusteeCerts,
    active_ca: &str,
    desired_ca: &str,
    now: DateTime<Utc>,
    grace_seconds: i32,
) -> Result<Duration> {
    retain_cert(certs, active_ca);
    retain_cert(certs, desired_ca);
    if certs.want_cert.as_deref() != Some(desired_ca) {
        certs.want_cert = Some(desired_ca.to_string());
        certs.want_since = Some(now.to_rfc3339());
    }
    let since = certs
        .want_since
        .as_deref()
        .context("want_since is missing")?;
    let since = DateTime::parse_from_rfc3339(since).context("want_since is not RFC3339")?;
    let deadline = since + chrono::TimeDelta::seconds(grace_seconds.into());
    Ok(deadline
        .signed_duration_since(now)
        .to_std()
        .unwrap_or_default())
}

/// Updates the certificate state after cutover by keeping only the active CA
/// in the Machine installation list, marking the others revoked, and clearing
/// the pending CA and timestamp.
fn revoke_other_certs(certs: &mut TrusteeCerts, active_ca: &str) {
    retain_cert(certs, active_ca);
    for cert in std::mem::take(&mut certs.machine_certs) {
        if cert != active_ca && !certs.revoked_certs.contains(&cert) {
            certs.revoked_certs.push(cert);
        }
    }
    certs.machine_certs.push(active_ca.to_string());
    certs.want_cert = None;
    certs.want_since = None;
}

/// Returns whether every non-deleting Machine owned by the TEC reports the
/// supplied CA's hash in its installed certificates. An empty set of eligible
/// Machines is ready.
fn machines_ready(machines: &[Machine], owner: &OwnerReference, ca: &str) -> bool {
    let hash = cert_hash(ca);
    machines
        .iter()
        .filter(|machine| {
            machine.metadata.deletion_timestamp.is_none() && owned_by(&machine.metadata, owner)
        })
        .all(|machine| {
            machine
                .status
                .as_ref()
                .and_then(|status| status.installed_certs.as_ref())
                .is_some_and(|installed| installed.contains(&hash))
        })
}

/// Publishes the initial Trustee CA to the TEC owner's `trustee-certs` ConfigMap
/// in the client's default namespace. Returns success once the CA is listed for
/// Machines to install.
pub async fn seed_machine_certs(client: &Client, owner: &OwnerReference, ca: &str) -> Result<()> {
    let maps: Api<ConfigMap> = Api::default_namespaced(client.clone());
    let (map, mut certs) = get_certs(&maps, owner).await?;
    retain_cert(&mut certs, ca);
    save_certs(&maps, map, &certs, owner).await
}

pub async fn reconcile_trustee(
    client: &Client,
    cluster: &TrustedExecutionCluster,
    owner: &OwnerReference,
) -> Result<(&'static str, Action)> {
    let Some(configured) = cluster.spec.trustee_secret.as_deref() else {
        return Ok((CERTS_UPDATED_REASON, LONG_REQUEUE));
    };
    let deployments: Api<Deployment> = Api::default_namespaced(client.clone());
    let deployment = deployments.get(TRUSTEE_DEPLOYMENT).await?;
    let managed = ensure_trustee_secret(client, configured, Some(&deployment), owner).await?;
    let active_ca = trustee_ca(&managed)?;
    let active_revision = trustee_revision(&managed)?;
    let (volume, _) = tls_mount(&deployment)?.context("Trustee Deployment has no TLS mount")?;
    let maps: Api<ConfigMap> = Api::default_namespaced(client.clone());
    let (map, mut certs) = get_certs(&maps, owner).await?;
    let rollout_reason = if certs.want_cert.as_deref() == Some(active_ca) {
        CERTS_REVOKING_OLD_REASON
    } else {
        CERTS_UPDATED_REASON
    };

    // If a previous reconcile persisted the Secret but could not restart the pods,
    // converge that revision before starting or cleaning up another rollout.
    if mounted_secret(volume)? != MANAGED_TRUSTEE_TLS
        || deployed_revision(&deployment) != Some(&active_revision)
    {
        let mut managed_volume = volume.clone();
        managed_volume.secret = tls_volume(MANAGED_TRUSTEE_TLS).0.secret;
        retain_cert(&mut certs, active_ca);
        save_certs(&maps, map, &certs, owner).await?;
        patch_tls_template(&deployments, &deployment, &managed_volume, &active_revision).await?;
        return Ok((rollout_reason, ROLLOUT_REQUEUE));
    }
    if !deployment_rollout_complete(&deployment) {
        return Ok((rollout_reason, ROLLOUT_REQUEUE));
    }

    let secrets: Api<Secret> = Api::default_namespaced(client.clone());
    let source = secrets.get(configured).await?;
    let desired = managed_secret(managed.clone(), &source, owner);
    if desired.data == managed.data
        && desired.annotations().get(TLS_SOURCE) == managed.annotations().get(TLS_SOURCE)
    {
        revoke_other_certs(&mut certs, active_ca);
        save_certs(&maps, map, &certs, owner).await?;
        return Ok((CERTS_UPDATED_REASON, LONG_REQUEUE));
    }

    let desired_ca = trustee_ca(&desired)?;
    let grace_seconds = cluster
        .spec
        .cert_update_grace_period
        .unwrap_or(DEFAULT_GRACE_SECONDS);
    let remaining = stage_ca(&mut certs, active_ca, desired_ca, Utc::now(), grace_seconds)?;
    save_certs(&maps, map, &certs, owner).await?;

    if active_ca != desired_ca && !remaining.is_zero() {
        // Read live Machines before cutover, including objects the watch has yet to deliver.
        let machines: Api<Machine> = Api::default_namespaced(client.clone());
        let list = machines.list(&Default::default()).await?;
        if !machines_ready(&list.items, owner, desired_ca) {
            return Ok((CERTS_ADDING_NEW_REASON, Action::requeue(remaining)));
        }
    }

    let revision = trustee_revision(&desired)?;
    secrets
        .replace(MANAGED_TRUSTEE_TLS, &Default::default(), &desired)
        .await?;
    if revision != active_revision {
        patch_tls_template(&deployments, &deployment, volume, &revision).await?;
    }
    Ok((CERTS_REVOKING_OLD_REASON, ROLLOUT_REQUEUE))
}

pub async fn reconcile_registration(
    client: &Client,
    deployment_name: &str,
    configured: Option<&str>,
) -> Result<()> {
    let Some(configured) = configured else {
        return Ok(());
    };
    let deployments: Api<Deployment> = Api::default_namespaced(client.clone());
    let Some(deployment) = deployments.get_opt(deployment_name).await? else {
        return Ok(());
    };
    let mounted = tls_mount(&deployment)?;
    let secrets: Api<Secret> = Api::default_namespaced(client.clone());
    let source = secrets.get(configured).await?;
    let revision = tls_revision(&source, configured)?;
    if let Some((current, _)) = mounted
        && mounted_secret(current)? == configured
        && deployed_revision(&deployment) == Some(revision.as_str())
    {
        return Ok(());
    }

    let (volume, mount) = tls_volume(configured);
    if let Some((current, _)) = mounted {
        let mut volume = current.clone();
        volume
            .secret
            .as_mut()
            .context("Missing TLS volume Secret")?
            .secret_name = Some(configured.to_string());
        return patch_tls_template(&deployments, &deployment, &volume, &revision).await;
    }

    // Older installs could start without TLS while waiting for the configured Secret.
    let mut args = deployment
        .spec
        .as_ref()
        .and_then(|spec| spec.template.spec.as_ref())
        .and_then(|pod| {
            pod.containers
                .iter()
                .find(|container| container.name == deployment_name)
        })
        .and_then(|container| container.args.clone())
        .unwrap_or_default();
    args.extend(registration_tls_args());
    deployments
        .patch(
            deployment_name,
            &PatchParams::default(),
            &Patch::Strategic(json!({
                "metadata": { "resourceVersion": deployment.metadata.resource_version },
                "spec": { "template": {
                    "metadata": { "annotations": { TLS_REVISION: revision } },
                    "spec": {
                    "volumes": [volume],
                    "containers": [{
                        "name": deployment_name,
                        "args": args,
                        "volumeMounts": [mount],
                    }]
                } } },
            })),
        )
        .await?;
    Ok(())
}

/// Reads the configured registration Secret in the client's default namespace.
/// Returns its volume, read-only mount, and TLS revision for the Pod template,
/// or `None` if the name is unset or the Secret is absent.
pub async fn registration_tls(
    client: &Client,
    configured: &Option<String>,
) -> Result<Option<(Volume, VolumeMount, String)>> {
    let Some(name) = configured else {
        return Ok(None);
    };
    let secrets: Api<Secret> = Api::default_namespaced(client.clone());
    let Some(secret) = secrets.get_opt(name).await? else {
        log::warn!("Configured TLS Secret {name} does not exist");
        return Ok(None);
    };
    let (volume, mount) = tls_volume(name);
    Ok(Some((volume, mount, tls_revision(&secret, name)?)))
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

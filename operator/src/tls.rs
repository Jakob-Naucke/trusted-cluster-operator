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

#[cfg(test)]
mod tests {
    use super::*;

    use http::{Method, Request, StatusCode};
    use k8s_openapi::ByteString;
    use k8s_openapi::api::apps::v1::DeploymentStatus;
    use kube::api::ObjectList;
    use kube::client::Body;
    use openssl::asn1::Asn1Time;
    use openssl::hash::MessageDigest;
    use openssl::pkey::{PKey, PKeyRef, Private};
    use openssl::x509::{X509, X509Name};
    use std::sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    };
    use trusted_cluster_operator_lib::MachineStatus;
    use trusted_cluster_operator_test_utils::mock_client::*;

    /// Returns a short-lived test certificate for the given name and key.
    /// Signs with the optional issuer and its key, or self-signs when absent.
    fn certificate(
        name: &str,
        key: &PKeyRef<Private>,
        issuer: Option<(&X509, &PKeyRef<Private>)>,
    ) -> X509 {
        let mut subject = X509Name::builder().unwrap();
        subject.append_entry_by_text("CN", name).unwrap();
        let subject = subject.build();
        let mut cert = X509::builder().unwrap();
        cert.set_subject_name(&subject).unwrap();
        let (issuer_name, signing_key) = issuer
            .map(|(cert, key)| (cert.subject_name(), key))
            .unwrap_or((&subject, key));
        cert.set_issuer_name(issuer_name).unwrap();
        cert.set_pubkey(key).unwrap();
        cert.set_not_before(&Asn1Time::days_from_now(0).unwrap())
            .unwrap();
        cert.set_not_after(&Asn1Time::days_from_now(1).unwrap())
            .unwrap();
        cert.sign(signing_key, MessageDigest::null()).unwrap();
        cert.build()
    }

    /// Returns a named TLS Secret fixture with a generated key and self-signed
    /// certificate to use as both the leaf and CA.
    fn source_secret(name: &str) -> Secret {
        let key = PKey::generate_ed25519().unwrap();
        let cert = certificate(name, &key, None).to_pem().unwrap();
        let data = BTreeMap::from([
            ("ca.crt".to_string(), ByteString(cert.clone())),
            ("tls.crt".to_string(), ByteString(cert)),
            (
                "tls.key".to_string(),
                ByteString(key.private_key_to_pem_pkcs8().unwrap()),
            ),
        ]);
        Secret {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                resource_version: Some("9".to_string()),
                ..Default::default()
            },
            data: Some(data),
            type_: Some("kubernetes.io/tls".to_string()),
            ..Default::default()
        }
    }

    /// Returns a test TEC with Trustee TLS configured and its matching owner
    /// reference for building related fixtures.
    fn cluster_and_owner() -> (TrustedExecutionCluster, OwnerReference) {
        let mut cluster = dummy_cluster();
        cluster.spec.trustee_secret = Some("configured-tls".to_string());
        let owner = operator::generate_owner_reference(&cluster).unwrap();
        (cluster, owner)
    }

    /// Returns a fully rolled-out Deployment fixture for the given Deployment
    /// and container names, mounted Secret, and optional TLS revision.
    fn test_deployment(
        name: &str,
        container: &str,
        secret: &str,
        revision: Option<String>,
    ) -> Deployment {
        let (volume, mount) = tls_volume(secret);
        serde_json::from_value(json!({
            "metadata": { "name": name, "generation": 2, "resourceVersion": "13" },
            "spec": {
                "selector": {},
                "template": {
                    "metadata": { "annotations": revision.map(|revision| BTreeMap::from([(TLS_REVISION, revision)])) },
                    "spec": {
                        "containers": [{ "name": container, "volumeMounts": [mount] }],
                        "volumes": [volume]
                    }
                }
            },
            "status": { "observedGeneration": 2, "replicas": 1, "updatedReplicas": 1, "availableReplicas": 1 }
        })).unwrap()
    }

    /// Returns a rolled-out Trustee Deployment fixture annotated with the
    /// supplied active managed Secret's revision.
    fn trustee_deployment(active: &Secret) -> Deployment {
        test_deployment(
            TRUSTEE_DEPLOYMENT,
            TRUSTEE_CONTAINER,
            MANAGED_TRUSTEE_TLS,
            Some(trustee_revision(active).unwrap()),
        )
    }

    /// Returns a managed Secret fixture for the source Secret and TEC owner,
    /// with a resource version for testing API replacements.
    fn managed_copy(source: &Secret, owner: &OwnerReference) -> Secret {
        let mut active = managed_secret(Secret::default(), source, owner);
        active.metadata.resource_version = Some("18".to_string());
        active
    }

    /// Returns a versioned `trustee-certs` ConfigMap fixture encoding the
    /// supplied certificate state under the given TEC owner.
    fn config_map(owner: &OwnerReference, certs: &TrusteeCerts) -> ConfigMap {
        ConfigMap {
            metadata: ObjectMeta {
                name: Some(TRUSTEE_CERTS_CONFIG_MAP.to_string()),
                owner_references: Some(vec![owner.clone()]),
                resource_version: Some("17".to_string()),
                ..Default::default()
            },
            data: Some(certs.to_config_map_data()),
            ..Default::default()
        }
    }

    /// Returns a Machine fixture for the supplied owner, with an installed
    /// certificate hash when a CA is supplied.
    fn machine(owner: &OwnerReference, ca: Option<&str>) -> Machine {
        let mut machine = Machine::new(
            "machine-1",
            trusted_cluster_operator_lib::MachineSpec {
                id: "1".to_string(),
                provider_id: None,
            },
        );
        machine.metadata.owner_references = Some(vec![owner.clone()]);
        machine.status = ca.map(|ca| MachineStatus {
            installed_certs: Some(vec![cert_hash(ca)]),
            conditions: None,
        });
        machine
    }

    /// Serializes a fixture into a successful JSON response for the mock API.
    fn to_json(value: &impl serde::Serialize) -> Result<String, StatusCode> {
        Ok(serde_json::to_string(value).unwrap())
    }

    /// Checks that staging the same CA preserves its grace deadline and staging
    /// a different CA resets it.
    #[test]
    fn grace_period_tracks_the_candidate_across_reconciles() {
        let mut certs = TrusteeCerts::default();
        let now = Utc::now();
        let grace = 60;
        let later = now + chrono::TimeDelta::seconds(15);
        assert_eq!(
            stage_ca(&mut certs, "old", "new", now, grace).unwrap(),
            Duration::from_secs(60)
        );
        assert_eq!(
            stage_ca(&mut certs, "old", "new", later, grace).unwrap(),
            Duration::from_secs(45)
        );
        let deadline = now + chrono::TimeDelta::seconds(60);
        assert!(
            stage_ca(&mut certs, "old", "new", deadline, grace)
                .unwrap()
                .is_zero()
        );
        certs.revoked_certs.push("alternate".to_string());
        assert_eq!(
            stage_ca(&mut certs, "old", "alternate", deadline, grace).unwrap(),
            Duration::from_secs(60)
        );
        assert!(certs.revoked_certs.is_empty());
        revoke_other_certs(&mut certs, "alternate");
        assert_eq!(certs.machine_certs, ["alternate"]);
        assert_eq!(certs.revoked_certs, ["old", "new"]);
        assert_eq!(certs.want_cert, None);
        assert_eq!(certs.want_since, None);
    }

    /// Checks that the operator publishes both CAs before waiting for TEC-owned
    /// Machines to report the requested CA.
    #[tokio::test]
    async fn publishes_both_cas_and_waits_for_owned_machines() {
        let (cluster, owner) = cluster_and_owner();
        let active = managed_copy(&source_secret("configured-tls"), &owner);
        let desired = source_secret("configured-tls");
        let deployment = trustee_deployment(&active);
        let machines = ObjectList {
            items: vec![machine(&owner, None)],
            types: Default::default(),
            metadata: Default::default(),
        };
        let state = (deployment, active, desired, machines);
        let clos = move |req: Request<Body>, n| {
            let (deployment, active, desired, machines) = state.clone();
            async move {
                match (req.method(), n) {
                    (&Method::GET, 0) => to_json(&deployment),
                    (&Method::GET, 1) => to_json(&active),
                    (&Method::GET, 2) => Err(StatusCode::NOT_FOUND),
                    (&Method::GET, 3) => to_json(&desired),
                    (&Method::POST, 4) => {
                        assert!(req.uri().path().ends_with("/configmaps"));
                        let map: ConfigMap =
                            serde_json::from_str(&get_body_string(req).await).unwrap();
                        let certs =
                            TrusteeCerts::from_config_map_data(map.data.as_ref().unwrap()).unwrap();
                        let desired_ca = trustee_ca(&desired).unwrap();
                        assert_eq!(
                            certs.machine_certs,
                            [trustee_ca(&active).unwrap(), desired_ca]
                        );
                        assert_eq!(certs.want_cert.as_deref(), Some(desired_ca));
                        assert!(
                            DateTime::parse_from_rfc3339(certs.want_since.as_deref().unwrap())
                                .is_ok()
                        );
                        to_json(&map)
                    }
                    (&Method::GET, 5) => to_json(&machines),
                    _ => panic!("unexpected request {n}: {req:?}"),
                }
            }
        };
        count_check!(6, clos, |client| {
            let (reason, _) = reconcile_trustee(&client, &cluster, &owner).await.unwrap();
            assert_eq!(reason, CERTS_ADDING_NEW_REASON);
        });
    }

    /// Checks that Machine readiness, grace expiry, or an unchanged CA each
    /// permits the managed Secret update and Trustee rollout.
    #[tokio::test]
    async fn cuts_over_when_machines_are_ready_grace_expires_or_ca_is_unchanged() {
        for (expired, same_ca) in [(false, false), (true, false), (false, true)] {
            let (mut cluster, owner) = cluster_and_owner();
            if expired {
                cluster.spec.cert_update_grace_period = Some(0);
            }
            let original = source_secret("old-tls");
            let active = managed_copy(&original, &owner);
            let mut desired = source_secret("configured-tls");
            if same_ca {
                let ca = X509::from_pem(secret_entry(&original, "ca.crt").unwrap()).unwrap();
                let ca_key =
                    PKey::private_key_from_pem(secret_entry(&original, "tls.key").unwrap())
                        .unwrap();
                let key = PKey::generate_ed25519().unwrap();
                let leaf = certificate("renewed", &key, Some((&ca, &ca_key)));
                desired.data = Some(BTreeMap::from([
                    ("ca.crt".to_string(), ByteString(ca.to_pem().unwrap())),
                    ("tls.crt".to_string(), ByteString(leaf.to_pem().unwrap())),
                    (
                        "tls.key".to_string(),
                        ByteString(key.private_key_to_pem_pkcs8().unwrap()),
                    ),
                ]));
            }
            let deployment = trustee_deployment(&active);
            let ca = trustee_ca(&desired).unwrap();
            let deployed_secret = managed_copy(&desired, &owner);
            let revision = trustee_revision(&deployed_secret).unwrap();
            let machines = ObjectList {
                items: vec![
                    machine(&owner, Some(ca)),
                    machine(&OwnerReference::default(), None),
                ],
                types: Default::default(),
                metadata: Default::default(),
            };
            let wait_for_machines = !expired && !same_ca;
            let promote = if wait_for_machines { 6 } else { 5 };
            let state = (deployment, active, desired, machines, revision);
            let clos = move |req: Request<Body>, n| {
                let (deployment, active, desired, machines, revision) = state.clone();
                async move {
                    match (req.method(), n) {
                        (&Method::GET, 0) => to_json(&deployment),
                        (&Method::GET, 1) => to_json(&active),
                        (&Method::GET, 2) => Err(StatusCode::NOT_FOUND),
                        (&Method::GET, 3) => to_json(&desired),
                        (&Method::POST, 4) => {
                            let map: ConfigMap =
                                serde_json::from_str(&get_body_string(req).await).unwrap();
                            let certs =
                                TrusteeCerts::from_config_map_data(map.data.as_ref().unwrap())
                                    .unwrap();
                            assert!(certs.revoked_certs.is_empty());
                            assert_eq!(certs.machine_certs.len(), if same_ca { 1 } else { 2 });
                            to_json(&map)
                        }
                        (&Method::GET, 5) if wait_for_machines => to_json(&machines),
                        (&Method::PUT, n) if n == promote => {
                            assert!(req.uri().path().ends_with(MANAGED_TRUSTEE_TLS));
                            let secret: Secret =
                                serde_json::from_str(&get_body_string(req).await).unwrap();
                            assert!(secret.data == desired.data);
                            assert_eq!(
                                secret.metadata.resource_version,
                                active.metadata.resource_version
                            );
                            to_json(&secret)
                        }
                        (&Method::PATCH, n) if n == promote + 1 => {
                            let patch: serde_json::Value =
                                serde_json::from_str(&get_body_string(req).await).unwrap();
                            assert_eq!(
                                patch["spec"]["template"]["metadata"]["annotations"][TLS_REVISION],
                                revision
                            );
                            to_json(&deployment)
                        }
                        _ => panic!("unexpected request {n}: {req:?}"),
                    }
                }
            };
            let count = Arc::new(AtomicU32::new(0));
            let client = MockClient::new(clos, "test".to_string(), count.clone()).into_client();
            let (reason, action) = reconcile_trustee(&client, &cluster, &owner).await.unwrap();
            assert_eq!(reason, CERTS_REVOKING_OLD_REASON);
            assert_eq!(action, ROLLOUT_REQUEUE);
            assert_eq!(count.load(Ordering::Acquire), promote + 2);
        }
    }

    /// Checks that a restart after updating the Secret resumes the pending
    /// rollout and that revocation waits until the rollout completes.
    #[tokio::test]
    async fn resumes_cutover_after_restart_and_revokes_only_after_rollout() {
        for phase in 0..3 {
            let (cluster, owner) = cluster_and_owner();
            let old = source_secret("old-tls");
            let desired = source_secret("configured-tls");
            let managed = managed_copy(&desired, &owner);
            let revision = trustee_revision(&managed).unwrap();
            let old_ca = trustee_ca(&old).unwrap().to_string();
            let new_ca = trustee_ca(&desired).unwrap().to_string();
            let mut certs = TrusteeCerts::default();
            stage_ca(
                &mut certs,
                &old_ca,
                &new_ca,
                Utc::now(),
                DEFAULT_GRACE_SECONDS,
            )
            .unwrap();
            let map = config_map(&owner, &certs);
            let mut deployment = if phase == 0 {
                trustee_deployment(&managed_copy(&old, &owner))
            } else {
                trustee_deployment(&managed)
            };
            if phase == 1 {
                deployment.status = Some(DeploymentStatus {
                    observed_generation: Some(1),
                    ..Default::default()
                });
            }
            let state = (deployment, managed, map, desired, revision, old_ca, new_ca);
            let clos = move |req: Request<Body>, n| {
                let (deployment, managed, map, desired, revision, old_ca, new_ca) = state.clone();
                async move {
                    match (req.method(), n) {
                        (&Method::GET, 0) => to_json(&deployment),
                        (&Method::GET, 1) => to_json(&managed),
                        (&Method::GET, 2) => to_json(&map),
                        (&Method::PATCH, 3) if phase == 0 => {
                            let patch: serde_json::Value =
                                serde_json::from_str(&get_body_string(req).await).unwrap();
                            assert_eq!(
                                patch["spec"]["template"]["metadata"]["annotations"][TLS_REVISION],
                                revision
                            );
                            to_json(&deployment)
                        }
                        (&Method::GET, 3) if phase == 2 => to_json(&desired),
                        (&Method::PUT, 4) if phase == 2 => {
                            let map: ConfigMap =
                                serde_json::from_str(&get_body_string(req).await).unwrap();
                            let certs =
                                TrusteeCerts::from_config_map_data(map.data.as_ref().unwrap())
                                    .unwrap();
                            assert_eq!(
                                certs.machine_certs.as_slice(),
                                std::slice::from_ref(&new_ca)
                            );
                            assert_eq!(
                                certs.revoked_certs.as_slice(),
                                std::slice::from_ref(&old_ca)
                            );
                            assert_eq!(certs.want_since, None);
                            to_json(&map)
                        }
                        _ => panic!("unexpected request {n} in phase {phase}: {req:?}"),
                    }
                }
            };
            let count = Arc::new(AtomicU32::new(0));
            let client = MockClient::new(clos, "test".to_string(), count.clone()).into_client();
            let (reason, _) = reconcile_trustee(&client, &cluster, &owner).await.unwrap();
            assert_eq!(
                reason,
                if phase == 2 {
                    CERTS_UPDATED_REASON
                } else {
                    CERTS_REVOKING_OLD_REASON
                }
            );
            assert_eq!(count.load(Ordering::Acquire), [4, 3, 5][phase]);
        }
    }

    /// Checks that migration seeds the managed Secret from the live legacy
    /// mount when the TEC already names a different source Secret.
    #[tokio::test]
    async fn adopts_the_legacy_mount_before_using_a_renamed_secret() {
        let (_, owner) = cluster_and_owner();
        let mut legacy = source_secret("legacy");
        legacy
            .data
            .as_mut()
            .unwrap()
            .insert("ca.crt".to_string(), ByteString(b"invalid PEM".to_vec()));
        let deployment = test_deployment(TRUSTEE_DEPLOYMENT, TRUSTEE_CONTAINER, "legacy", None);
        let owner_for_api = owner.clone();
        let clos = move |req: Request<Body>, n| {
            let legacy = legacy.clone();
            let owner_for_api = owner_for_api.clone();
            async move {
                match (req.method(), n) {
                    (&Method::GET, 0) => {
                        assert!(req.uri().path().ends_with(MANAGED_TRUSTEE_TLS));
                        Err(StatusCode::NOT_FOUND)
                    }
                    (&Method::GET, 1) => {
                        assert!(req.uri().path().ends_with("/secrets/legacy"));
                        to_json(&legacy)
                    }
                    (&Method::POST, 2) => {
                        let copy: Secret =
                            serde_json::from_str(&get_body_string(req).await).unwrap();
                        assert!(copy.data == legacy.data);
                        assert_eq!(copy.annotations()[TLS_SOURCE], "legacy");
                        assert!(owned_by(&copy.metadata, &owner_for_api));
                        to_json(&copy)
                    }
                    _ => panic!("unexpected request {n}: {req:?}"),
                }
            }
        };
        count_check!(3, clos, |client| {
            ensure_trustee_secret(&client, "configured-tls", Some(&deployment), &owner)
                .await
                .unwrap();
        });
    }

    /// Checks that a Secret rename or in-place certificate update changes the
    /// registration Pod template revision and preserves the container spec.
    #[tokio::test]
    async fn rolls_registration_on_secret_name_or_certificate_change() {
        for (name, previous_secret) in [
            ("attestation-key-register", "old-tls"),
            ("register-server", "new-tls"),
        ] {
            let previous = source_secret(previous_secret);
            let deployed_revision = tls_revision(&previous, previous_secret).unwrap();
            let deployment = test_deployment(name, name, previous_secret, Some(deployed_revision));
            let mut source = source_secret("new-tls");
            source
                .data
                .as_mut()
                .unwrap()
                .insert("tls.key".to_string(), ByteString(b"invalid PEM".to_vec()));
            let clos = move |req: Request<Body>, n| {
                let deployment = deployment.clone();
                let source = source.clone();
                async move {
                    match (req.method(), n) {
                        (&Method::GET, 0) => to_json(&deployment),
                        (&Method::GET, 1) => {
                            assert!(req.uri().path().ends_with("/secrets/new-tls"));
                            to_json(&source)
                        }
                        (&Method::PATCH, 2) => {
                            let patch: serde_json::Value =
                                serde_json::from_str(&get_body_string(req).await).unwrap();
                            let pod = &patch["spec"]["template"]["spec"];
                            assert!(pod.get("containers").is_none());
                            assert_eq!(pod["volumes"][0]["name"], "serving-tls");
                            assert_eq!(pod["volumes"][0]["secret"]["secretName"], "new-tls");
                            assert_eq!(
                                patch["spec"]["template"]["metadata"]["annotations"][TLS_REVISION],
                                tls_revision(&source, "new-tls").unwrap()
                            );
                            to_json(&deployment)
                        }
                        _ => panic!("unexpected request {n}: {req:?}"),
                    }
                }
            };
            count_check!(3, clos, |client| {
                reconcile_registration(&client, name, Some("new-tls"))
                    .await
                    .unwrap();
            });
        }
    }

    /// Checks that a Deployment whose mounted Secret and revision already match
    /// the desired state receives no rollout patch.
    #[tokio::test]
    async fn unchanged_registration_certificate_does_not_roll_again() {
        let name = "register-server";
        let source = source_secret("current-tls");
        let revision = tls_revision(&source, "current-tls").unwrap();
        let deployment = test_deployment(name, name, "current-tls", Some(revision));
        let state = (deployment, source);
        let clos = move |req: Request<Body>, n| {
            let (deployment, source) = state.clone();
            async move {
                match (req.method(), n) {
                    (&Method::GET, 0) => to_json(&deployment),
                    (&Method::GET, 1) => to_json(&source),
                    _ => panic!("unexpected request {n}: {req:?}"),
                }
            }
        };
        count_check!(2, clos, |client| {
            reconcile_registration(&client, name, Some("current-tls"))
                .await
                .unwrap();
        });
    }
}

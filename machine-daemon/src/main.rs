// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::ConfigMap;
use kube::api::{Patch, PatchParams};
use kube::runtime::controller::{Action, Controller};
use kube::{Api, Client, Resource, runtime::watcher};
use log::{info, warn};
use std::{collections::HashSet, process::Command, sync::Arc};

use clevis_pin_trustee_lib::{Config, Server};
use trusted_cluster_operator_lib::{conditions::*, trustee_certs::*, *};

/// Field manager used for this daemon's Server-Side Apply patches
const FIELD_MANAGER: &str = "machine-daemon";
/// Pin name used for the Trustee Clevis binding
const TRUSTEE_PIN: &str = "trustee";

/// Info from the Trustee Clevis binding
#[derive(Debug)]
pub struct Binding {
    pub slot: u32,
    pub config: Config,
}

/// Parses the output of `clevis luks list -d DEV`
pub fn parse_bindings(output: &str) -> Result<Vec<Binding>> {
    let not_empty = |line: &&str| !line.trim().is_empty();
    let parse = |line| parse_binding_line(line).transpose();
    output.lines().filter(not_empty).filter_map(parse).collect()
}

/// Parses a single `clevis luks list` line, returning `None` for non-Trustee pins
fn parse_binding_line(line: &str) -> Result<Option<Binding>> {
    let malformed = format!("malformed clevis luks list line: {line}");
    let mut parts = line.splitn(3, ' ');

    let stripped_slot = parts.next().and_then(|s| s.strip_suffix(':'));
    let parse = |s: &str| s.parse().ok();
    let slot = stripped_slot.and_then(parse).context(malformed.clone())?;

    if parts.next().context(malformed.clone())? != TRUSTEE_PIN {
        return Ok(None);
    }
    let config_json = parts.next().context(malformed.clone())?.trim_matches('\'');
    let config = serde_json::from_str(config_json).context(malformed)?;
    Ok(Some(Binding { slot, config }))
}

/// Extracts the machine UUID from a Trustee config's KBS resource `path`
/// (`default/<uuid>/root`, set at provisioning time by register-server)
pub fn machine_uuid(config: &Config) -> Result<&str> {
    let uuid = config.path.split('/').nth(1);
    uuid.filter(|u| !u.is_empty())
        .context(format!("unexpected trustee resource path: {}", config.path))
}

/// Name of the Machine resource for a Trustee config, as created by register-server
pub fn machine_name(config: &Config) -> Result<String> {
    Ok(format!("machine-{}", machine_uuid(config)?))
}

/// Computes the Clevis config that should replace `current`, given the target state
/// from the `trustee-certs` ConfigMap: one server entry per `machine_certs` entry,
/// all sharing the Trustee URL already present in `current`
pub fn desired_config(current: &Config, machine_certs: &[String]) -> Result<Config> {
    let existing_server = current.servers.first();
    let ctx = "current Clevis config has no servers to take a Trustee URL from";
    let url = existing_server.map(|s| &s.url).context(ctx)?;
    let make = |cert: &String| Server {
        url: url.clone(),
        cert: cert.clone(),
    };
    Ok(Config {
        servers: machine_certs.iter().map(make).collect(),
        path: current.path.clone(),
        initdata: current.initdata.clone(),
        num_retries: current.num_retries.clone(),
        attestation_key: current.attestation_key.clone(),
    })
}

/// True if `desired`'s servers differ from `current`'s, ignoring order
pub fn servers_changed(current: &Config, desired: &Config) -> bool {
    fn certs(config: &Config) -> HashSet<(&str, &str)> {
        let servers = config.servers.iter();
        let pairs = servers.map(|server| (server.url.as_str(), server.cert.as_str()));
        pairs.collect()
    }
    certs(current) != certs(desired)
}

/// Runs a command chrooted into `MACHINE_DAEMON_HOST_ROOT`, the node's root filesystem
/// mounted into the daemon's container
fn chroot_output(args: &[&str]) -> Result<String> {
    let program = args[0];
    let output = Command::new("chroot")
        .arg(MACHINE_DAEMON_HOST_ROOT)
        .args(args)
        .output()
        .context(format!("failed to run {program}"))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(anyhow!("{program} failed: {stderr}",));
    }
    String::from_utf8(output.stdout).context(format!("{program} output was not UTF-8"))
}

/// Finds the LUKS block device backing the CoreOS `/sysroot` mount
pub fn find_root_device() -> Result<String> {
    // TODO This finds e.g. `/dev/mapper/root` but we are looking for e.g. `/dev/sda4`
    let device = chroot_output(&["findmnt", "-n", "-o", "SOURCE", "/sysroot"])?;
    let device = device.trim().to_string();
    if device.is_empty() {
        return Err(anyhow!("findmnt returned no device for /sysroot"));
    }
    Ok(device)
}

/// Lists the Clevis bindings on `device`
pub fn list_bindings(device: &str) -> Result<Vec<Binding>> {
    let stdout = chroot_output(&["clevis", "luks", "list", "-d", device])?;
    parse_bindings(&stdout)
}

/// Replaces the config of the Clevis binding in `slot` on `device`
pub fn edit_binding(device: &str, slot: u32, config: &Config) -> Result<()> {
    let config_json = serde_json::to_string(config)?;
    let slot = slot.to_string();
    let mut cmd = vec!["clevis", "luks", "edit"];
    cmd.extend_from_slice(&["-d", device, "-s", &slot, "-c", &config_json]);
    chroot_output(&cmd)?;
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger_init();
    let client = Client::try_default().await?;
    let config_maps: Api<ConfigMap> = Api::default_namespaced(client.clone());
    let watcher_config =
        watcher::Config::default().fields(&format!("metadata.name={TRUSTEE_CERTS_CONFIG_MAP}"));
    Controller::new(config_maps, watcher_config)
        .run(reconcile, controller_error_policy, Arc::new(client))
        .for_each(controller_info)
        .await;
    Ok(())
}

async fn reconcile(
    config_map: Arc<ConfigMap>,
    client: Arc<Client>,
) -> Result<Action, ControllerError> {
    let machines: Api<Machine> = Api::default_namespaced((*client).clone());

    let empty = Default::default();
    let data = config_map.data.as_ref().unwrap_or(&empty);
    let certs =
        TrusteeCerts::from_config_map_data(data).context("malformed trustee-certs ConfigMap")?;

    let device = find_root_device()?;
    let bindings = list_bindings(&device)?;
    let ctx = "no clevis-pin-trustee slot found";
    let binding = bindings.first().context(ctx)?;
    let current = &binding.config;
    let name = machine_name(current)?;

    let desired = desired_config(current, &certs.machine_certs)?;
    if !servers_changed(current, &desired) {
        patch_status(&machines, &name, CERTS_UPDATED_REASON, &current.servers).await?;
        return Ok(LONG_REQUEUE);
    }

    patch_status(&machines, &name, CERTS_UPDATING_REASON, &current.servers).await?;
    match edit_binding(&device, binding.slot, &desired) {
        Ok(()) => {
            info!("Updated Clevis header for {name}");
            patch_status(&machines, &name, CERTS_UPDATED_REASON, &desired.servers).await?;
        }
        Err(e) => {
            warn!("Failed to update Clevis header for {name}: {e:#}");
            let reason = CERTS_UPDATE_FAILED_REASON;
            patch_status(&machines, &name, reason, &current.servers).await?;
        }
    }
    Ok(LONG_REQUEUE)
}

async fn patch_status(
    machines: &Api<Machine>,
    name: &str,
    reason: &str,
    installed_servers: &[Server],
) -> Result<()> {
    let machine = machines.get(name).await?;
    let condition = certs_updated_condition(reason, machine.metadata.generation, &machine.status);
    let hash = |server: &Server| cert_hash(&server.cert);
    let installed_certs: Vec<String> = installed_servers.iter().map(hash).collect();

    let unchanged = has_condition(&machine.status, CERTS_UPDATED_CONDITION, reason)
        && machine
            .status
            .as_ref()
            .and_then(|status| status.installed_certs.as_deref())
            == Some(installed_certs.as_slice());
    if unchanged {
        return Ok(());
    }

    let patch = Patch::Apply(serde_json::json!({
        "apiVersion": Machine::api_version(&Default::default()),
        "kind": Machine::kind(&Default::default()),
        "status": {
            "conditions": [condition],
            "installedCerts": installed_certs,
        }
    }));
    machines
        .patch_status(name, &PatchParams::apply(FIELD_MANAGER), &patch)
        .await
        .map_err(Into::<anyhow::Error>::into)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE_LINE: &str = r#"1: trustee '{"initdata":null,"num_retries":72,"path":"default/e29150dd-6f78-4393-b3e6-4c8e3d73a992/root","servers":[{"cert":"-----BEGIN CERTIFICATE-----\nMIID\n-----END CERTIFICATE-----\n","url":"https://131.189.209.120:8080"}]}'"#;

    #[test]
    fn parses_example_binding() {
        let bindings = parse_bindings(EXAMPLE_LINE).unwrap();
        assert_eq!(bindings.len(), 1);
        let binding = &bindings[0];
        assert_eq!(binding.slot, 1);
        assert_eq!(binding.config.servers.len(), 1);
        assert_eq!(
            binding.config.servers[0].url,
            "https://131.189.209.120:8080"
        );
        assert_eq!(
            machine_uuid(&binding.config).unwrap(),
            "e29150dd-6f78-4393-b3e6-4c8e3d73a992"
        );
        assert_eq!(
            machine_name(&binding.config).unwrap(),
            "machine-e29150dd-6f78-4393-b3e6-4c8e3d73a992"
        );
    }

    #[test]
    fn parses_multiple_bindings_and_skips_non_trustee_pins() {
        let output = format!("0: tpm2 '{{\"pcr_bank\":\"sha256\"}}'\n{EXAMPLE_LINE}\n");
        let bindings = parse_bindings(&output).unwrap();
        assert_eq!(bindings.len(), 1);
        assert_eq!(bindings[0].slot, 1);
    }

    #[test]
    fn no_trustee_binding_is_empty() {
        let bindings = parse_bindings("0: tpm2 '{\"pcr_bank\":\"sha256\"}'").unwrap();
        assert!(bindings.is_empty());
    }

    #[test]
    fn malformed_line_errors() {
        assert!(parse_bindings("not a binding line").is_err());
    }

    fn config_with_servers(servers: Vec<(&str, &str)>) -> Config {
        Config {
            servers: servers
                .into_iter()
                .map(|(url, cert)| Server {
                    url: url.to_string(),
                    cert: cert.to_string(),
                })
                .collect(),
            path: "default/some-uuid/root".to_string(),
            initdata: None,
            num_retries: None,
            attestation_key: None,
        }
    }

    #[test]
    fn desired_config_replicates_machine_certs() {
        let current = config_with_servers(vec![("https://kbs:8080", "cert-a")]);
        let machine_certs = vec!["cert-a".to_string(), "cert-b".to_string()];
        let desired = desired_config(&current, &machine_certs).unwrap();
        assert_eq!(desired.servers.len(), 2);
        assert!(desired.servers.iter().all(|s| s.url == "https://kbs:8080"));
        assert!(servers_changed(&current, &desired));
    }

    #[test]
    fn desired_config_replicates_duplicate_certs() {
        let current = config_with_servers(vec![("https://kbs:8080", "cert-a")]);
        let machine_certs = vec!["cert-a".to_string(), "cert-a".to_string()];
        let desired = desired_config(&current, &machine_certs).unwrap();
        assert_eq!(desired.servers.len(), 2);
    }

    #[test]
    fn desired_config_unchanged_is_not_reported_changed() {
        let current = config_with_servers(vec![("https://kbs:8080", "cert-a")]);
        let machine_certs = vec!["cert-a".to_string()];
        let desired = desired_config(&current, &machine_certs).unwrap();
        assert!(!servers_changed(&current, &desired));
    }

    #[test]
    fn desired_config_without_existing_servers_errors() {
        let current = config_with_servers(vec![]);
        assert!(desired_config(&current, &["cert-a".to_string()]).is_err());
    }
}

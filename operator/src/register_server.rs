// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use k8s_openapi::api::apps::v1::{Deployment, DeploymentSpec};
use k8s_openapi::api::core::v1::{
    Container, ContainerPort, PodSpec, PodTemplateSpec, Secret, SecretVolumeSource, Service,
    ServicePort, ServiceSpec, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::{
    apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference},
    util::intstr::IntOrString,
};
use kube::runtime::{
    controller::{Action, Controller},
    finalizer,
    finalizer::Event,
};
use kube::{Api, Client, Resource};
use log::{info, warn};
use std::{collections::BTreeMap, sync::Arc};

use crate::trustee;
use operator::*;
use trusted_cluster_operator_lib::Machine;

const INTERNAL_REGISTER_SERVER_PORT: i32 = 8000;
/// Finalizer name to discard decryption keys when a machine is deleted
const MACHINE_FINALIZER: &str = "finalizer.machine.trusted-execution-clusters.io";
const TLS_DIR: &str = "/etc/tls";

async fn read_certificates(
    client: Client,
    secret: &Option<String>,
) -> Result<(Vec<String>, Vec<Volume>, Vec<VolumeMount>)> {
    let mut args = vec![
        "--port".to_string(),
        INTERNAL_REGISTER_SERVER_PORT.to_string(),
    ];
    let mut volumes = Vec::new();
    let mut volume_mounts = Vec::new();

    let secrets: Api<Secret> = Api::default_namespaced(client.clone());
    if secret.is_none() {
        return Ok((args, volumes, volume_mounts));
    }
    let secret_name = secret.as_ref().unwrap();
    let secret = secrets.get(secret_name).await;
    if let Ok(secret) = secret {
        let err = "TLS secret had no name";
        let name = secret.metadata.name.context(err)?;
        args.push("--cert-path".to_string());
        args.push(format!("{TLS_DIR}/tls.crt"));
        args.push("--key-path".to_string());
        args.push(format!("{TLS_DIR}/tls.key"));
        volumes.push(Volume {
            name: name.clone(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(name.clone()),
                ..Default::default()
            }),
            ..Default::default()
        });
        volume_mounts.push(VolumeMount {
            name,
            mount_path: TLS_DIR.to_string(),
            ..Default::default()
        });
    } else {
        warn!("Certificate secret {secret_name} was provided, but could not be retrieved");
    }

    Ok((args, volumes, volume_mounts))
}

pub async fn create_register_server_deployment(
    client: Client,
    owner_reference: OwnerReference,
    image: &str,
    secret: &Option<String>,
) -> Result<()> {
    let name = "register-server";
    let app_label = "register-server";
    let labels = BTreeMap::from([("app".to_string(), app_label.to_string())]);

    let (args, volumes, volume_mounts) = read_certificates(client.clone(), secret).await?;
    let deployment = Deployment {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: Some(DeploymentSpec {
            replicas: Some(1),
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels.clone()),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    service_account_name: Some("trusted-cluster-operator".to_string()),
                    containers: vec![Container {
                        name: name.to_string(),
                        image: Some(image.to_string()),
                        ports: Some(vec![ContainerPort {
                            container_port: INTERNAL_REGISTER_SERVER_PORT,
                            ..Default::default()
                        }]),
                        args: Some(args),
                        volume_mounts: Some(volume_mounts),
                        ..Default::default()
                    }],
                    volumes: Some(volumes),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    };

    create_or_info_if_exists!(client, Deployment, deployment);
    info!("Register server deployment created successfully");
    Ok(())
}

pub async fn create_register_server_service(
    client: Client,
    owner_reference: OwnerReference,
    register_server_port: Option<i32>,
) -> Result<()> {
    let name = "register-server";
    let app_label = "register-server";
    let labels = BTreeMap::from([("app".to_string(), app_label.to_string())]);

    let service = Service {
        metadata: ObjectMeta {
            name: Some(name.to_string()),
            labels: Some(labels.clone()),
            owner_references: Some(vec![owner_reference]),
            ..Default::default()
        },
        spec: Some(ServiceSpec {
            selector: Some(labels),
            ports: Some(vec![ServicePort {
                name: Some("http".to_string()),
                port: register_server_port.unwrap_or(INTERNAL_REGISTER_SERVER_PORT),
                target_port: Some(IntOrString::Int(INTERNAL_REGISTER_SERVER_PORT)),
                protocol: Some("TCP".to_string()),
                ..Default::default()
            }]),
            type_: Some("ClusterIP".to_string()),
            ..Default::default()
        }),
        ..Default::default()
    };

    create_or_info_if_exists!(client, Service, service);
    info!("Register server service created successfully");
    Ok(())
}

async fn keygen_reconcile(
    machine: Arc<Machine>,
    client: Arc<Client>,
) -> Result<Action, ControllerError> {
    let machines: Api<Machine> = Api::default_namespaced(Arc::unwrap_or_clone(client.clone()));
    finalizer(&machines, MACHINE_FINALIZER, machine, |ev| async move {
        match ev {
            Event::Apply(machine) => {
                let kube_client = Arc::unwrap_or_clone(client);
                let id = &machine.spec.id.clone();
                async {
                    let owner_reference = generate_owner_reference(&Arc::unwrap_or_clone(machine))?;
                    trustee::generate_secret(kube_client.clone(), id, owner_reference).await?;
                    trustee::mount_secret(kube_client, id).await
                }
                .await
                .map(|_| Action::await_change())
                .map_err(|e| finalizer::Error::<ControllerError>::ApplyFailed(e.into()))
            }
            Event::Cleanup(machine) => {
                let kube_client = Arc::unwrap_or_clone(client);
                let id = &machine.spec.id;
                trustee::unmount_secret(kube_client, id)
                    .await
                    .map(|_| Action::await_change())
                    .map_err(|e| finalizer::Error::<ControllerError>::CleanupFailed(e.into()))
            }
        }
    })
    .await
    .map_err(|e| anyhow!("failed to reconcile on machine: {e}").into())
}

pub async fn launch_keygen_controller(client: Client) {
    let machines: Api<Machine> = Api::default_namespaced(client.clone());
    tokio::spawn(
        Controller::new(machines, Default::default())
            .run(keygen_reconcile, controller_error_policy, Arc::new(client))
            .for_each(controller_info),
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use trusted_cluster_operator_test_utils::mock_client::*;

    #[tokio::test]
    async fn test_create_reg_server_depl_success() {
        let clos =
            |client| create_register_server_deployment(client, Default::default(), "image", &None);
        test_create_success::<_, _, Deployment>(clos).await;
    }

    #[tokio::test]
    async fn test_create_reg_server_depl_error() {
        let clos =
            |client| create_register_server_deployment(client, Default::default(), "image", &None);
        test_create_error(clos).await;
    }

    #[tokio::test]
    async fn test_create_reg_server_svc_success() {
        let clos = |client| create_register_server_service(client, Default::default(), None);
        test_create_success::<_, _, Service>(clos).await;
    }

    #[tokio::test]
    async fn test_create_reg_server_svc_error() {
        let clos = |client| create_register_server_service(client, Default::default(), Some(80));
        test_create_error(clos).await;
    }
}

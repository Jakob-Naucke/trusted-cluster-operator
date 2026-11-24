// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use std::collections::BTreeMap;

use anyhow::Result;
use k8s_openapi::api::apps::v1::{DaemonSet, DaemonSetSpec};
use k8s_openapi::api::core::v1::{
    Affinity, Container, HostPathVolumeSource, NodeAffinity, NodeSelector, NodeSelectorRequirement,
    NodeSelectorTerm, PodSpec, PodTemplateSpec, SecurityContext, Toleration, Volume, VolumeMount,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta, OwnerReference};
use kube::api::{Patch, PatchParams};
use kube::{Api, Client};
use trusted_cluster_operator_lib::{MACHINE_DAEMON_HOST_ROOT, MACHINE_NODE_LABEL};

pub const MACHINE_DAEMON_NAME: &str = "trusted-cluster-machine-daemon";

/// Builds the privileged machine daemon DaemonSet for the given TEC owner and
/// container image. The returned spec selects Linux nodes with the machine label
/// and mounts the host root for Clevis updates.
fn daemon_set(owner: OwnerReference, image: &str) -> DaemonSet {
    // TODO get image from env without default after rebase
    let labels = BTreeMap::from([("app".to_string(), MACHINE_DAEMON_NAME.to_string())]);
    let volume_name = "host-root";

    DaemonSet {
        metadata: ObjectMeta {
            name: Some(MACHINE_DAEMON_NAME.to_string()),
            owner_references: Some(vec![owner]),
            ..Default::default()
        },
        spec: Some(DaemonSetSpec {
            selector: LabelSelector {
                match_labels: Some(labels.clone()),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    service_account_name: Some(MACHINE_DAEMON_NAME.to_string()),
                    automount_service_account_token: Some(true),
                    // Clevis runs in the chroot and may use a host-local DNS resolver.
                    host_network: Some(true),
                    dns_policy: Some("ClusterFirstWithHostNet".to_string()),
                    node_selector: Some(BTreeMap::from([(
                        "kubernetes.io/os".to_string(),
                        "linux".to_string(),
                    )])),
                    affinity: Some(Affinity {
                        node_affinity: Some(NodeAffinity {
                            required_during_scheduling_ignored_during_execution: Some(
                                NodeSelector {
                                    node_selector_terms: vec![NodeSelectorTerm {
                                        match_expressions: Some(vec![NodeSelectorRequirement {
                                            key: MACHINE_NODE_LABEL.to_string(),
                                            operator: "Exists".to_string(),
                                            ..Default::default()
                                        }]),
                                        ..Default::default()
                                    }],
                                },
                            ),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    tolerations: Some(vec![Toleration {
                        operator: Some("Exists".to_string()),
                        ..Default::default()
                    }]),
                    containers: vec![Container {
                        name: "machine-daemon".to_string(),
                        image: Some(image.to_string()),
                        security_context: Some(SecurityContext {
                            privileged: Some(true),
                            run_as_user: Some(0),
                            read_only_root_filesystem: Some(true),
                            ..Default::default()
                        }),
                        volume_mounts: Some(vec![VolumeMount {
                            name: volume_name.to_string(),
                            mount_path: MACHINE_DAEMON_HOST_ROOT.to_string(),
                            mount_propagation: Some("HostToContainer".to_string()),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }],
                    volumes: Some(vec![Volume {
                        name: volume_name.to_string(),
                        host_path: Some(HostPathVolumeSource {
                            path: "/".to_string(),
                            type_: Some("Directory".to_string()),
                        }),
                        ..Default::default()
                    }]),
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

pub async fn reconcile(client: &Client, owner: OwnerReference, image: &str) -> Result<()> {
    let daemon_sets: Api<DaemonSet> = Api::default_namespaced(client.clone());
    daemon_sets
        .patch(
            MACHINE_DAEMON_NAME,
            &PatchParams::apply("machine-daemon-deployment"),
            &Patch::Apply(daemon_set(owner, image)),
        )
        .await?;
    Ok(())
}

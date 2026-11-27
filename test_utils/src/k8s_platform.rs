// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, anyhow};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{
    LoadBalancerStatus, Service, ServicePort, ServiceSpec, ServiceStatus,
};
use kube::api::{ObjectMeta, Patch};
use kube::runtime::wait::await_condition;
use kube::{Api, Client};
use serde_json::json;
use std::{collections::BTreeMap, env};
use tokio::time::timeout;

use crate::{ANSI_RESET, PLATFORM_ENV, Poller, YELLOW, log_time, scaled_duration, test_warn};
use trusted_cluster_operator_lib::{certificates::*, endpoints::*};

const CLUSTER_URL_ENV: &str = "CLUSTER_URL";
const SET_CLUSTER_ERR: &str = "Set $CLUSTER_URL when $PLATFORM is none of: kind, openshift";
const EXPOSE_MAX_ATTEMPTS: u32 = 3;
const KIND_TRUSTEE_PORT: i32 = 31000;
const KIND_REGISTER_SERVER_PORT: i32 = 31001;
const KIND_ATTESTATION_KEY_REGISTER_PORT: i32 = 31002;

#[async_trait::async_trait]
#[auto_impl::auto_impl(Box)]
pub trait K8sPlatform: Send + Sync {
    fn add_scc(&self, kustomization: &mut serde_yaml::Value);
    async fn expose(
        &self,
        service: &str,
        deployment: &str,
        cert_name: &str,
        test_name: &str,
    ) -> Result<()>;
    async fn get_cluster_url(&self, service: &str, port: Option<i32>) -> Result<String>;
}

struct Kind {
    public: bool,
    client: Client,
    namespace: String,
}
struct OpenShift {
    client: Client,
    namespace: String,
}
struct OtherK8s {}

pub fn get_k8s_platform(client: &Client, namespace: &str) -> Box<dyn K8sPlatform> {
    let client = client.clone();
    let namespace = namespace.to_string();
    match env::var(PLATFORM_ENV).as_deref().unwrap_or("kind") {
        "kind" => Box::new(Kind {
            public: false,
            client,
            namespace,
        }),
        "kind_public" => Box::new(Kind {
            public: true,
            client,
            namespace,
        }),
        "openshift" => Box::new(OpenShift { client, namespace }),
        _ => Box::new(OtherK8s {}),
    }
}

#[async_trait::async_trait]
impl K8sPlatform for Kind {
    fn add_scc(&self, _: &mut serde_yaml::Value) {}
    async fn expose(&self, service: &str, _: &str, _: &str, _: &str) -> Result<()> {
        if !self.public {
            return Ok(());
        }
        let (app_label, port, node_port) = match service {
            TRUSTEE_SERVICE => Ok((TRUSTEE_APP_LABEL, TRUSTEE_PORT, KIND_TRUSTEE_PORT)),
            REGISTER_SERVER_SERVICE => Ok((
                REGISTER_SERVER_APP_LABEL,
                REGISTER_SERVER_PORT,
                KIND_REGISTER_SERVER_PORT,
            )),
            ATTESTATION_KEY_REGISTER_SERVICE => Ok((
                ATTESTATION_KEY_REGISTER_APP_LABEL,
                ATTESTATION_KEY_REGISTER_PORT,
                KIND_ATTESTATION_KEY_REGISTER_PORT,
            )),
            s => Err(anyhow!("unknown service: {s}")),
        }?;
        let service_port = ServicePort {
            name: Some("http".to_string()),
            node_port: Some(node_port),
            port,
            ..Default::default()
        };
        let services: Api<Service> = Api::namespaced(self.client.clone(), &self.namespace);
        let service = Service {
            metadata: ObjectMeta {
                name: Some(format!("{service}-forward")),
                ..Default::default()
            },
            spec: Some(ServiceSpec {
                type_: Some("NodePort".to_string()),
                ports: Some(vec![service_port]),
                selector: Some(BTreeMap::from([("app".to_string(), app_label.to_string())])),
                ..Default::default()
            }),
            ..Default::default()
        };
        services.create(&Default::default(), &service).await?;
        Ok(())
    }

    async fn get_cluster_url(&self, service: &str, port: Option<i32>) -> Result<String> {
        let url = format!("{service}.{}.svc.cluster.local", self.namespace);
        Ok(match port {
            Some(port) => format!("{url}:{port}"),
            None => url,
        })
    }
}

enum OpenShiftHost {
    Ip(String),
    Hostname(String),
    None,
}

impl OpenShift {
    async fn get_url(&self, service: &str) -> OpenShiftHost {
        let services: Api<Service> = Api::namespaced(self.client.clone(), &self.namespace);
        let Ok(svc) = services.get(service).await else {
            return OpenShiftHost::None;
        };
        let ingress = &svc.status.unwrap().load_balancer.unwrap().ingress.unwrap()[0];
        match (&ingress.hostname, &ingress.ip) {
            (Some(hostname), _) => OpenShiftHost::Hostname(hostname.clone()),
            (_, Some(ip)) => OpenShiftHost::Ip(ip.clone()),
            (None, None) => OpenShiftHost::None,
        }
    }
}

#[async_trait::async_trait]
impl K8sPlatform for OpenShift {
    fn add_scc(&self, kustomization: &mut serde_yaml::Value) {
        let err = "unexpected kustomization";
        let resources = kustomization.get_mut("resources").expect(err);
        let resource_seq = resources.as_sequence_mut().expect(err);
        resource_seq.push(serde_yaml::Value::String("scc.yaml".to_string()))
    }

    async fn expose(
        &self,
        service: &str,
        deployment: &str,
        cert_name: &str,
        _: &str,
    ) -> Result<()> {
        let services: Api<Service> = Api::namespaced(self.client.clone(), &self.namespace);
        let pp = Default::default();
        let duration = scaled_duration(120);
        let lb = json!({ "spec": { "type": "LoadBalancer" } });
        let clusterip = Patch::Merge(json!({ "spec": { "type": "ClusterIP" } }));

        let mut url = OpenShiftHost::None;
        let mut last_err: Option<anyhow::Error> = None;
        for attempt in 1..=EXPOSE_MAX_ATTEMPTS {
            services.patch(service, &pp, &Patch::Merge(&lb)).await?;

            let has_ingress = |svc: Option<&Service>| {
                let chk_lb = |bal: &LoadBalancerStatus| bal.ingress.is_some();
                let chk_st = |st: &ServiceStatus| st.load_balancer.as_ref().map(chk_lb);
                let chk_svc = |svc: &Service| svc.status.as_ref().and_then(chk_st);
                svc.and_then(chk_svc).unwrap_or(false)
            };
            let ctx = format!(
                "waiting for ingress on {service} (attempt {attempt}/{EXPOSE_MAX_ATTEMPTS})"
            );
            let ingress_ready = await_condition(services.clone(), service, has_ingress);
            match timeout(duration, ingress_ready).await {
                Err(_) => {
                    last_err = Some(anyhow!(ctx));
                    services.patch(service, &pp, &clusterip).await?;
                    continue;
                }
                Ok(Err(e)) => {
                    last_err = Some(anyhow::Error::from(e).context(ctx));
                    services.patch(service, &pp, &clusterip).await?;
                    continue;
                }
                Ok(Ok(_)) => {}
            }

            url = self.get_url(service).await;
            if let OpenShiftHost::Hostname(ref name) = url {
                let target = format!("{name}:0");
                let msg =
                    format!("{name} not DNS-resolvable (attempt {attempt}/{EXPOSE_MAX_ATTEMPTS})");
                let chk = || async { tokio::net::lookup_host(&target).await.map(|_| ()) };
                let poller = Poller::new().with_timeout(duration);
                if let Err(e) = poller.with_error_message(msg).poll_async(chk).await {
                    last_err = Some(e);
                    services.patch(service, &pp, &clusterip).await?;
                    continue;
                }
            }

            last_err = None;
            break;
        }
        if let Some(e) = last_err {
            return Err(e);
        }

        let certs: Api<Certificate> = Api::namespaced(self.client.clone(), &self.namespace);
        let cert = certs.get(cert_name).await?;
        let old_revision = cert.status.and_then(|st| st.revision).unwrap_or(0);
        let cert_patch = match url {
            OpenShiftHost::Ip(ip) => json!({
                "spec": {
                    "ipAddresses": [ip],
                    "dnsNames": [],
                }
            }),
            OpenShiftHost::Hostname(name) => json!({
                "spec": {
                    "dnsNames": [name],
                    "ipAddresses": []
                }
            }),
            OpenShiftHost::None => {
                return Err(anyhow!("expected service {service}"));
            }
        };
        let cert_merge = Patch::Merge(cert_patch);
        certs.patch(cert_name, &pp, &cert_merge).await?;

        let cert_reissued = |cert: Option<&Certificate>| {
            let chk = |st: &CertificateStatus| st.revision.map(|r| r > old_revision);
            cert.and_then(|c| c.status.as_ref().and_then(chk))
                .unwrap_or(false)
        };
        let cert_done = await_condition(certs, cert_name, cert_reissued);
        let ctx = format!("waiting for cert {cert_name} to have a rev newer than {old_revision}");
        timeout(duration, cert_done).await.context(ctx)??;

        let deployments: Api<Deployment> = Api::namespaced(self.client.clone(), &self.namespace);
        deployments.restart(deployment).await?;

        Ok(())
    }

    async fn get_cluster_url(&self, service: &str, port: Option<i32>) -> Result<String> {
        let append_port = |e| match port {
            Some(p) => format!("{e}:{p}"),
            None => e,
        };
        Ok(match self.get_url(service).await {
            OpenShiftHost::Ip(ip) => append_port(ip),
            OpenShiftHost::Hostname(name) => append_port(name),
            // Service did not exist yet, put empty name in cert and patch upon expose
            OpenShiftHost::None => String::new(),
        })
    }
}

#[async_trait::async_trait]
impl K8sPlatform for OtherK8s {
    fn add_scc(&self, _: &mut serde_yaml::Value) {}

    async fn expose(&self, _: &str, _: &str, _: &str, test_name: &str) -> Result<()> {
        let warn = "You appear to be on an environment that is not Kind or OpenShift. \
                    Ensure operator services are reachable";
        test_warn!(test_name, "{warn}");
        Ok(())
    }

    async fn get_cluster_url(&self, _: &str, _: Option<i32>) -> Result<String> {
        Err(anyhow!(SET_CLUSTER_ERR))
    }
}

pub async fn get_cluster_url(
    client: &Client,
    namespace: &str,
    service: &str,
    port: Option<i32>,
) -> Result<String> {
    if let Ok(url) = env::var(CLUSTER_URL_ENV) {
        let full_url = format!("{service}.{namespace}.{url}");
        return Ok(match port {
            Some(port) => format!("{full_url}:{port}"),
            None => full_url,
        });
    }
    get_k8s_platform(client, namespace)
        .get_cluster_url(service, port)
        .await
}

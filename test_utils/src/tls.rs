// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{Condition, Time};
use k8s_openapi::jiff::Timestamp;
use kube::api::{ObjectMeta, Patch};
use kube::runtime::wait::await_condition;
use kube::{Api, Client};
use percent_encoding::{NON_ALPHANUMERIC, utf8_percent_encode};
use tokio::time::timeout;

use crate::k8s_platform::get_cluster_url;
use crate::{scaled_duration, scaled_timeout, wait_for_resource_created};
use trusted_cluster_operator_lib::{certificates::*, endpoints::*, issuers::*};

pub const ROOT_CERT: &str = "root-cert";
const ROOT_SECRET: &str = "root-secret";
pub const REG_SECRET: &str = "reg-srv-secret";
pub const TRUSTEE_SECRET: &str = "trustee-secret";
pub const ATT_REG_SECRET: &str = "att-reg-secret";
pub const REG_CERT: &str = "reg-srv-cert";
pub const TRUSTEE_CERT: &str = "trustee-cert";
pub const ATT_REG_CERT: &str = "att-reg-cert";

pub async fn get_encoded_root_pem(client: Client, namespace: &str) -> Result<String> {
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let root_secret = secrets.get(ROOT_SECRET).await?;
    let ctx = format!("Root secret {ROOT_SECRET} had no ca.crt");
    let root_secret_data = root_secret.data.context(ctx.clone())?;
    let ca_pem_bytes = root_secret_data.get("ca.crt").context(ctx)?;
    let root_pem = String::from_utf8(ca_pem_bytes.0.clone())?;
    let encoded = utf8_percent_encode(&root_pem, NON_ALPHANUMERIC);
    Ok(format!("data:,{encoded}"))
}

pub async fn create_certificate(
    client: &Client,
    namespace: &str,
    service_name: &str,
    cert_name: &str,
    secret_name: &str,
    issuer_name: &str,
) -> Result<()> {
    let domain = get_cluster_url(client, namespace, service_name, None).await?;
    let certs: Api<Certificate> = Api::namespaced(client.clone(), namespace);
    let cert = Certificate {
        metadata: ObjectMeta {
            name: Some(cert_name.to_string()),
            ..Default::default()
        },
        spec: CertificateSpec {
            secret_name: secret_name.to_string(),
            issuer_ref: CertificateIssuerRef {
                name: issuer_name.to_string(),
                ..Default::default()
            },
            dns_names: Some(vec![domain]),
            ..Default::default()
        },
        ..Default::default()
    };
    certs.create(&Default::default(), &cert).await?;
    Ok(())
}

pub async fn set_certificates(client: &Client, namespace: &str) -> anyhow::Result<()> {
    let root_issuer_name = "root-issuer";
    let root_issuer = Issuer {
        metadata: ObjectMeta {
            name: Some(root_issuer_name.to_string()),
            ..Default::default()
        },
        spec: IssuerSpec {
            self_signed: Some(Default::default()),
            ..Default::default()
        },
        ..Default::default()
    };
    let issuers: Api<Issuer> = Api::namespaced(client.clone(), namespace);
    issuers.create(&Default::default(), &root_issuer).await?;
    let root_cert = Certificate {
        metadata: ObjectMeta {
            name: Some(ROOT_CERT.to_string()),
            ..Default::default()
        },
        spec: CertificateSpec {
            secret_name: ROOT_SECRET.to_string(),
            is_ca: Some(true),
            issuer_ref: CertificateIssuerRef {
                name: root_issuer_name.to_string(),
                ..Default::default()
            },
            common_name: Some("selfsigned-ca".to_string()),
            ..Default::default()
        },
        ..Default::default()
    };
    let certs: Api<Certificate> = Api::namespaced(client.clone(), namespace);
    certs.create(&Default::default(), &root_cert).await?;
    let issuer_name = "issuer";
    let issuer = Issuer {
        metadata: ObjectMeta {
            name: Some(issuer_name.to_string()),
            ..Default::default()
        },
        spec: IssuerSpec {
            ca: Some(IssuerCa {
                secret_name: ROOT_SECRET.to_string(),
                ..Default::default()
            }),
            ..Default::default()
        },
        ..Default::default()
    };
    issuers.create(&Default::default(), &issuer).await?;

    let svc = REGISTER_SERVER_SERVICE;
    create_certificate(client, namespace, svc, REG_CERT, REG_SECRET, issuer_name).await?;
    let svc = TRUSTEE_SERVICE;
    let secret = TRUSTEE_SECRET;
    create_certificate(client, namespace, svc, TRUSTEE_CERT, secret, issuer_name).await?;
    let svc = ATTESTATION_KEY_REGISTER_SERVICE;
    let secret = ATT_REG_SECRET;
    create_certificate(client, namespace, svc, ATT_REG_CERT, secret, issuer_name).await?;

    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    for secret in [REG_SECRET, TRUSTEE_SECRET, ATT_REG_SECRET] {
        wait_for_resource_created(&secrets, secret, scaled_timeout(60)).await?;
    }
    Ok(())
}

pub async fn renew_certificate(client: &Client, namespace: &str, name: &str) -> Result<()> {
    let certs: Api<Certificate> = Api::namespaced(client.clone(), namespace);
    let cert = certs.get(name).await?;
    let status = cert.status.unwrap_or_default();
    let old_revision = status.revision.unwrap_or_default();
    let mut conditions = status.conditions.unwrap_or_default();
    conditions.retain(|condition| condition.type_ != "Issuing");
    conditions.push(Condition {
        type_: "Issuing".to_string(),
        status: "True".to_string(),
        reason: "ManuallyTriggered".to_string(),
        message: "rolling for test".to_string(),
        last_transition_time: Time(Timestamp::now()),
        observed_generation: None,
    });
    let patch = Patch::Merge(&serde_json::json!({
        "metadata": { "resourceVersion": cert.metadata.resource_version },
        "status": { "conditions": conditions },
    }));
    let params = Default::default();
    certs.patch_status(name, &params, &patch).await?;

    let renewed = await_condition(certs, name, |cert: Option<&Certificate>| {
        cert.and_then(|cert| cert.status.as_ref()?.revision)
            .is_some_and(|revision| revision > old_revision)
    });
    timeout(scaled_duration(120), renewed)
        .await
        .context(format!("waiting for certificate {name} to renew"))??;
    Ok(())
}

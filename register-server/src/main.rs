// SPDX-FileCopyrightText: Alice Frosi <afrosi@redhat.com>
// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{anyhow, Context};
use axum::response::{IntoResponse, Json};
use axum::{extract::ConnectInfo, http::StatusCode};
use axum::{routing::get, Router};
use axum_server::tls_openssl::OpenSSLConfig;
use clap::Parser;
use clevis_pin_trustee_lib::{Config as ClevisConfig, Server as ClevisServer};
use env_logger::Env;
use ignition_config::v3_5::{
    Clevis, ClevisCustom, Config as IgnitionConfig, Filesystem, Luks, Storage,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;
use kube::{Api, Client};
use log::{error, info};
use std::net::SocketAddr;
use uuid::Uuid;

use trusted_cluster_operator_lib::{Machine, MachineSpec, TrustedExecutionCluster};

#[derive(Parser)]
#[command(name = "register-server")]
#[command(about = "HTTP server that generates Clevis PINs with random UUIDs")]
struct Args {
    #[arg(short, long, default_value = "8000")]
    port: u16,
    #[arg(long)]
    cert_path: Option<String>,
    #[arg(long)]
    key_path: Option<String>,
}

fn generate_ignition(id: &str, public_addr: &str) -> IgnitionConfig {
    let clevis_conf = ClevisConfig {
        servers: vec![ClevisServer {
            url: format!("http://{public_addr}"),
            cert: "".to_string(),
        }],
        path: format!("default/{id}/root"),
        initdata: None,
        // TODO add initdata, e.g.
        // #[derive(Serialize)]
        // struct Initdata {
        //     uuid: String,
        // }
        // let initdata = Initdata {
        //     uuid: id.to_string(),
        // };
        // ... initdata: serde_json::to_string(&initdata)?,
        // depending on ultimate design decision
    };

    let luks_root = "root";

    let mut fs = Filesystem::new(format!("/dev/mapper/{luks_root}"));
    fs.format = Some("ext4".to_string());
    fs.label = Some(luks_root.to_string());
    fs.wipe_filesystem = Some(true);

    let mut luks = Luks::new(luks_root.to_string());
    luks.clevis = Some(Clevis {
        custom: Some(ClevisCustom {
            config: Some(serde_json::to_string(&clevis_conf).unwrap()),
            needs_network: Some(true),
            pin: Some("trustee".to_string()),
        }),
        ..Default::default()
    });
    luks.device = Some(format!("/dev/disk/by-partlabel/{luks_root}"));
    luks.label = Some(luks_root.to_string());
    luks.wipe_volume = Some(true);

    IgnitionConfig {
        storage: Some(Storage {
            filesystems: Some(vec![fs]),
            luks: Some(vec![luks]),
            ..Default::default()
        }),
        ..Default::default()
    }
}

async fn get_public_trustee_addr(client: Client) -> anyhow::Result<String> {
    let namespace = client.default_namespace().to_string();
    let clusters: Api<TrustedExecutionCluster> = Api::default_namespaced(client);
    let params = Default::default();
    let mut list = clusters.list(&params).await?;
    if list.items.is_empty() {
        return Err(anyhow!(
            "No TrustedExecutionCluster found in namespace {namespace}. \
             Ensure that this register-server is in the same namespace \
             as the TrustedExecutionCluster you're targeting.
             Cancelling Ignition Clevis PIN request.",
        ));
    } else if list.items.len() > 1 {
        return Err(anyhow!(
            "More than one TrustedExecutionCluster found in namespace {namespace}. \
             trusted-cluster-operator does not support more than one TrustedExecutionCluster. \
             Cancelling Ignition Clevis PIN request.",
        ));
    }
    let cluster = list.items.pop().unwrap();
    let name = cluster.metadata.name.as_deref().unwrap_or("<no name>");
    cluster.spec.public_trustee_addr.context(format!(
        "TrustedExecutionCluster {name} did not specify a public Trustee address. \
         Add an address and re-register the node."
    ))
}

async fn register_handler(ConnectInfo(addr): ConnectInfo<SocketAddr>) -> impl IntoResponse {
    let id = Uuid::new_v4().to_string();
    let client_ip = addr.ip().to_string();

    info!("Registration request from IP: {client_ip}");

    let internal_error = |e: anyhow::Error| {
        let code = StatusCode::INTERNAL_SERVER_ERROR;
        error!("{e:?}");
        let msg = serde_json::json!({
            "code": code.as_u16(),
            "message": format!("{e:#}")
        });
        (code, Json(msg))
    };

    let kube_client = match Client::try_default().await {
        Ok(c) => c,
        Err(e) => return internal_error(e.into()),
    };
    match create_machine(kube_client.clone(), &id, &client_ip).await {
        Ok(_) => info!("Machine created successfully: machine-{id}"),
        Err(e) => return internal_error(e.context("Failed to create machine")),
    }
    let public_addr = match get_public_trustee_addr(kube_client).await {
        Ok(a) => a,
        Err(e) => return internal_error(e.context("Failed to get Trustee address")),
    };

    let ignition = generate_ignition(&id, &public_addr);
    let json = match serde_json::to_value(ignition) {
        Ok(json) => json,
        Err(e) => return internal_error(anyhow!("Failed to serialise Ignition: {e}")),
    };
    (StatusCode::OK, Json(json))
}

async fn create_machine(client: Client, uuid: &str, client_ip: &str) -> anyhow::Result<()> {
    let machines: Api<Machine> = Api::default_namespaced(client);

    // Check for existing machines with the same IP
    let machine_list = machines.list(&Default::default()).await?;

    for existing_machine in machine_list.items {
        if existing_machine.spec.registration_address == client_ip {
            if let Some(name) = &existing_machine.metadata.name {
                info!("Found existing machine {name} with IP {client_ip}, deleting...");
                machines.delete(name, &Default::default()).await?;
                info!("Deleted existing machine: {name}");
            }
        }
    }

    let machine_name = format!("machine-{uuid}");
    let machine = Machine {
        metadata: ObjectMeta {
            name: Some(machine_name.clone()),
            ..Default::default()
        },
        spec: MachineSpec {
            id: uuid.to_string(),
            registration_address: client_ip.to_string(),
        },
        status: None,
    };

    machines.create(&Default::default(), &machine).await?;
    info!("Created Machine: {machine_name} with IP: {client_ip}");
    Ok(())
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(Env::default().default_filter_or("info")).init();

    let args = Args::parse();
    let app = Router::new().route("/ignition-clevis-pin-trustee", get(register_handler));
    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    let service = app.into_make_service_with_connect_info::<SocketAddr>();
    info!("Starting server on http://{}", addr);

    let run = if args.cert_path.is_some() && args.key_path.is_some() {
        let config = OpenSSLConfig::from_pem_file(args.cert_path.unwrap(), args.key_path.unwrap())
            .expect("invalid PEM files");
        axum_server::bind_openssl(addr, config).serve(service).await
    } else {
        axum_server::bind(addr).serve(service).await
    };
    run.expect("Server failed");
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{Method, Request};
    use kube::api::ObjectList;
    use trusted_cluster_operator_test_utils::mock_client::*;

    const TEST_IP: &str = "12.34.56.78";

    fn dummy_clusters() -> ObjectList<TrustedExecutionCluster> {
        ObjectList {
            types: Default::default(),
            metadata: Default::default(),
            items: vec![dummy_cluster()],
        }
    }

    #[tokio::test]
    async fn test_get_public_trustee_addr() {
        let clos = async |_, _| Ok(serde_json::to_string(&dummy_clusters()).unwrap());
        count_check!(1, clos, |client| {
            let addr = get_public_trustee_addr(client).await.unwrap();
            assert_eq!(addr, "::".to_string());
        });
    }

    #[tokio::test]
    async fn test_get_public_trustee_addr_none() {
        let clos = async |_, _| {
            let mut clusters = dummy_clusters();
            clusters.items.clear();
            Ok(serde_json::to_string(&clusters).unwrap())
        };
        count_check!(1, clos, |client| {
            let err = get_public_trustee_addr(client).await.err().unwrap();
            assert!(err.to_string().contains("No TrustedExecutionCluster found"));
        });
    }

    #[tokio::test]
    async fn test_get_public_trustee_addr_multiple() {
        let clos = async |_, _| {
            let mut clusters = dummy_clusters();
            clusters.items.push(clusters.items[0].clone());
            Ok(serde_json::to_string(&clusters).unwrap())
        };
        count_check!(1, clos, |client| {
            let err = get_public_trustee_addr(client).await.err().unwrap();
            assert!(err.to_string().contains("More than one"));
        });
    }

    #[tokio::test]
    async fn test_get_public_trustee_no_addr() {
        let clos = async |_, _| {
            let mut clusters = dummy_clusters();
            clusters.items[0].spec.public_trustee_addr = None;
            Ok(serde_json::to_string(&clusters).unwrap())
        };
        count_check!(1, clos, |client| {
            let err = get_public_trustee_addr(client).await.err().unwrap();
            let contains = "did not specify a public Trustee address";
            assert!(err.to_string().contains(contains));
        });
    }

    #[tokio::test]
    async fn test_get_public_trustee_error() {
        test_get_error(async |c| get_public_trustee_addr(c).await.map(|_| ())).await;
    }

    fn dummy_machine() -> Machine {
        Machine {
            metadata: ObjectMeta {
                name: Some("test".to_string()),
                ..Default::default()
            },
            spec: MachineSpec {
                id: "test".to_string(),
                registration_address: TEST_IP.to_string(),
            },
            status: None,
        }
    }

    fn dummy_machines() -> ObjectList<Machine> {
        ObjectList {
            types: Default::default(),
            metadata: Default::default(),
            items: vec![dummy_machine()],
        }
    }

    #[tokio::test]
    async fn test_create_machine() {
        let clos = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::GET) => Ok(serde_json::to_string(&dummy_machines()).unwrap()),
            (1, &Method::POST) => Ok(serde_json::to_string(&dummy_machine()).unwrap()),
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(2, clos, |client| {
            assert!(create_machine(client, "test", "::").await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_create_machine_existing_ip() {
        let clos = async |req: Request<_>, ctr| match (ctr, req.method()) {
            (0, &Method::GET) => Ok(serde_json::to_string(&dummy_machines()).unwrap()),
            (1, &Method::DELETE) | (2, &Method::POST) => {
                Ok(serde_json::to_string(&dummy_machine()).unwrap())
            }
            _ => panic!("unexpected API interaction: {req:?}, counter {ctr}"),
        };
        count_check!(3, clos, |client| {
            assert!(create_machine(client, "test", TEST_IP).await.is_ok());
        });
    }

    #[tokio::test]
    async fn test_create_machine_error() {
        test_get_error(async |c| create_machine(c, "test", TEST_IP).await.map(|_| ())).await;
    }
}

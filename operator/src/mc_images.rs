// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result, anyhow};
use futures_util::StreamExt;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelectorRequirement;
use kube::Client;
use kube::core::{Expression, Selector, SelectorExt};
use kube::runtime::reflector::ObjectRef;
use kube::runtime::{Controller, controller::Action};
use kube::runtime::{finalizer, finalizer::Event};
use kube::{Api, ResourceExt, api::ObjectMeta};
use log::warn;
use std::{collections::BTreeMap, sync::Arc};

use operator::*;
use trusted_cluster_operator_lib::machineconfigpools::MachineConfigPool;
use trusted_cluster_operator_lib::machineconfigs::MachineConfig;
use trusted_cluster_operator_lib::reference_values::{OSIMAGE_RESOURCE_PREFIX, rfc1035};
use trusted_cluster_operator_lib::*;

const MC_FINALIZER: &str = "trusted-execution-clusters.io/machineconfig";
const MC_LABEL: &str = "trusted-execution-clusters.io/based-on-machineconfig";

/// Check if MCP's label selectors would select MC
fn is_live(mcp: &MachineConfigPool, mc: &MachineConfig) -> bool {
    let Some(ref labels) = mc.metadata.labels else {
        return false;
    };
    let selector = &mcp.spec.machine_config_selector;
    let match_exps = selector.as_ref().and_then(|s| s.match_expressions.clone());
    let match_labels = selector.as_ref().and_then(|s| s.match_labels.clone());
    // Only consider matched when there were any criteria at all
    let match_any = match_exps.is_some() || match_labels.is_some();

    let exp_match = match_exps.is_none_or(|exps| {
        let mut selector = Selector::default();
        for mcp_exp in exps {
            let exp = Expression::try_from(LabelSelectorRequirement {
                key: mcp_exp.key,
                operator: mcp_exp.operator,
                values: mcp_exp.values,
            });
            if let Ok(exp) = exp {
                selector.extend(exp);
            } else if let Err(e) = exp {
                let name = mcp.name_any();
                warn!("failed to parse MCP {name}'s match expression: {e}",);
            };
        }
        selector.matches(labels)
    });

    let label_match =
        match_labels.is_none_or(|ls| ls.iter().all(|(k, v)| labels.get(k) == Some(v)));
    match_any && exp_match && label_match
}

fn is_stored(image: &ApprovedImage, mc: &MachineConfig) -> bool {
    match (image.metadata.labels.as_ref(), mc.metadata.name.as_ref()) {
        (Some(labels), Some(name)) => labels.get(MC_LABEL).is_some_and(|m| *m == *name),
        _ => false,
    }
}

async fn add_approved_image(mc: &MachineConfig, ctx: &OperatorContext) -> Result<Action> {
    let err = "MachineConfig changed, but had no name";
    let mc_name = mc.metadata.name.as_ref().context(err)?;
    let url = match mc.spec.os_image_url.clone() {
        Some(url) if !url.is_empty() => url,
        _ => {
            warn!("Registered MC {mc_name}, but it had no osImageURL");
            return Ok(LONG_REQUEUE);
        }
    };

    let image_name = rfc1035(&format!("{mc_name}-{url}"), OSIMAGE_RESOURCE_PREFIX)?;
    let labels = BTreeMap::from([(MC_LABEL.to_string(), mc_name.to_string())]);
    let image = ApprovedImage {
        metadata: ObjectMeta {
            name: Some(image_name),
            labels: Some(labels),
            ..Default::default()
        },
        spec: ApprovedImageSpec { image: url },
        status: None,
    };
    create_or_info_if_exists(ctx.client.clone(), &image).await?;
    Ok(LONG_REQUEUE)
}

async fn delete_approved_image(image: &ApprovedImage, client: Client) -> Result<()> {
    let err = "ApprovedImage for deletion found, but had no name";
    let image_name = image.metadata.name.as_ref().context(err)?;
    let images: Api<ApprovedImage> = Api::default_namespaced(client);
    images.delete(image_name, &Default::default()).await?;
    Ok(())
}

async fn handle_machineconfig(mc: &MachineConfig, ctx: &OperatorContext) -> Result<Action> {
    let live = ctx.mcp_store.find(|mcp| is_live(mcp, mc)).is_some();
    if let Some(stored) = ctx.image_store.find(|i| is_stored(i, mc)) {
        let url = mc.spec.os_image_url.as_ref();
        // Delete if moved out of scope or URL out of date
        if !live || url.is_none_or(|url| *url != stored.spec.image) {
            delete_approved_image(&stored, ctx.client.clone()).await?;
        }
    }
    if !live {
        return Ok(LONG_REQUEUE);
    }
    add_approved_image(mc, ctx).await
}

async fn find_and_delete_approved_image(
    mc: &MachineConfig,
    ctx: &OperatorContext,
) -> Result<Action> {
    let Some(image) = ctx.image_store.find(|i| is_stored(i, mc)) else {
        let mc_name = mc.name_any();
        warn!("MachineConfig {mc_name} deleted, but no associated ApprovedImage found");
        return Ok(LONG_REQUEUE);
    };
    delete_approved_image(&image, ctx.client.clone()).await?;
    Ok(LONG_REQUEUE)
}

async fn mc_reconcile(
    mc: Arc<MachineConfig>,
    ctx: Arc<OperatorContext>,
) -> Result<Action, ControllerError> {
    let mcs: Api<MachineConfig> = Api::all(ctx.client.clone());
    finalizer(&mcs, MC_FINALIZER, mc, |ev| async move {
        match ev {
            Event::Apply(mc) => handle_machineconfig(&mc, &ctx)
                .await
                .map_err(|e| finalizer::Error::<ControllerError>::ApplyFailed(e.into())),
            Event::Cleanup(mc) => find_and_delete_approved_image(&mc, &ctx)
                .await
                .map_err(|e| finalizer::Error::<ControllerError>::CleanupFailed(e.into())),
        }
    })
    .await
    .map_err(|e| anyhow!("failed to reconcile on MachineConfig: {e}").into())
}

pub async fn launch_rv_mc_controller(ctx: Arc<OperatorContext>) {
    let mcs: Api<MachineConfig> = Api::all(ctx.client.clone());
    let mcps: Api<MachineConfigPool> = Api::all(ctx.client.clone());
    let mcp_ctx = ctx.clone();
    tokio::spawn(
        Controller::new(mcs, Default::default())
            .watches(mcps, Default::default(), move |mcp| {
                let mcs = mcp_ctx.mc_store.state_filter(|mc| is_live(&mcp, mc));
                mcs.into_iter()
                    .filter_map(|mc| mc.metadata.name.as_deref().map(ObjectRef::new))
                    .collect::<Vec<_>>()
            })
            .run(mc_reconcile, controller_error_policy, ctx)
            .for_each(controller_info),
    );
}

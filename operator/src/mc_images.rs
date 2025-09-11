// SPDX-FileCopyrightText: Jakob Naucke <jnaucke@redhat.com>
//
// SPDX-License-Identifier: MIT

// TODO can you gate this without nesting in a module?
#[cfg(feature = "openshift")]
pub mod img {
    use std::sync::Arc;

    use anyhow::{Context, Result};
    use futures_util::StreamExt;
    use kube::Api;
    use kube::api::ObjectMeta;
    use kube::runtime::Controller;
    use kube::runtime::controller::Action;
    use kube::runtime::reflector::ObjectRef;
    use log::warn;

    use crate::reference_values::rfc1035;
    use operator::*;
    use trusted_cluster_operator_lib::machineconfigpools::MachineConfigPool;
    use trusted_cluster_operator_lib::*;

    // TODO remove/own

    async fn mcp_reconcile(
        mcp: Arc<MachineConfigPool>,
        ctx: Arc<OperatorContext>,
    ) -> Result<Action, ControllerError> {
        let err = "MCP changed, but had no name";
        let mcp_name = &mcp.metadata.name.clone().context(err)?;
        let mut err = format!("MCP {mcp_name} changed, but had no configuration");
        let config = &mcp.spec.configuration.clone().context(err)?;
        err = format!("MCP {mcp_name} changed, but config had no name");
        let config_name = &config.name.clone().context(err)?;

        let obj_ref = ObjectRef::new(config_name);
        let err_ctx = format!("Missing MC {config_name}");
        let mc = ctx.mc_store.get(&obj_ref).context(err_ctx)?;
        let Some(url) = mc.spec.os_image_url.clone() else {
            warn!("Registered MC {config_name}, but it had no osImageURL");
            return Ok(LONG_REQUEUE);
        };

        let image = ApprovedImage {
            metadata: ObjectMeta {
                name: Some(rfc1035(&url, "osimage")?),
                ..Default::default()
            },
            spec: ApprovedImageSpec { image: url },
            status: None,
        };
        let images: Api<ApprovedImage> = Api::default_namespaced(ctx.client.clone());
        let result = images.create(&Default::default(), &image).await;
        result.map_err(|e| Into::<ControllerError>::into(Into::<anyhow::Error>::into(e)))?;
        Ok(LONG_REQUEUE)
    }

    pub async fn launch_rv_mcp_controller(ctx: Arc<OperatorContext>) {
        let mcps: Api<MachineConfigPool> = Api::all(ctx.client.clone());
        tokio::spawn(
            Controller::new(mcps, Default::default())
                .run(mcp_reconcile, controller_error_policy, ctx)
                .for_each(controller_info),
        );
    }
}

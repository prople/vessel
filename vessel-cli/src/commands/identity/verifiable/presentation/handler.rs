use prople_vessel_core::identity::verifiable::presentation::types::PresentationEntityAccessor;
use rst_common::with_logging::log::{debug, info};

use prople_jsonrpc_client::types::Executor;

use prople_vessel_rpc::components::presentation::{
    Method, MethodDomain, Param, ParamDomain, CorePresentationModel,
};

use prople_vessel_rpc::build_rpc_method;

use crate::commands::agents::get_agent_address;
use crate::commands::handler::ContextHandler;

use crate::models::identity::account::types::DID;
use crate::models::db::DB;
use crate::models::identity::verifiable::presentation::Presentation;
use crate::models::types::AgentName;

use crate::types::CliError;
use crate::utils::rpc::build_client;

use super::PresentationCommands;

pub async fn handle_commands(
    ctx: &ContextHandler,
    commands: PresentationCommands,
) -> Result<(), CliError> {
    debug!("account command handler triggered...");

    let db = DB::new(ctx.db());
    let agent = ctx
        .agent()
        .ok_or(CliError::AgentError(String::from("missing agent")))?;

    match commands {
        PresentationCommands::Generate(args) => {
            debug!(
                "[presentation:generate] agent from context: {}",
                ctx.agent().unwrap_or(String::from("empty agent"))
            );

            let method = build_rpc_method(Method::Domain(MethodDomain::Generate));
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<CorePresentationModel>();
            let resp = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::Generate {
                        password: args.password,
                        did_issuer: args.from_did,
                        credentials: args.credentials,
                    })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let rpc_resp = resp
                .result
                .ok_or(CliError::RpcError(String::from("missing result")))?;

            let holder = rpc_resp
                .get_vp()
                .holder
                .ok_or(CliError::RpcError(String::from("missing holder")))?;

            let presentation = Presentation::new(
                rpc_resp.get_id(),
                DID::from(holder.as_str()),
                rpc_resp.clone(),
            );
            
            let _ = db
                .save(AgentName::from(agent.clone()), presentation.clone())
                .await
                .map_err(|err| CliError::DBError(err.to_string()))?;
            
            info!("Presentation generated successfully");
        },
    }
    Ok(())
}

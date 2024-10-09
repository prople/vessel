use rst_common::standard::serde_json;
use rst_common::with_logging::log::{debug, info};

use prople_jsonrpc_client::types::Executor;

use prople_vessel_core::identity::account::types::AccountEntityAccessor;
use prople_vessel_rpc::build_rpc_method;
use prople_vessel_rpc::components::account::{CoreAccountModel, Method, Param, ParamDomain};

use crate::commands::agents::get_agent_address;
use crate::commands::handler::ContextHandler;

use crate::models::db::DB;
use crate::models::identity::account::account::Account;
use crate::models::identity::account::types::DID;
use crate::models::types::AgentName;

use crate::types::CliError;
use crate::utils::rpc::build_client;

use super::AccountCommands;

pub async fn handle_commands(
    ctx: &ContextHandler,
    commands: AccountCommands,
) -> Result<(), CliError> {
    debug!("account command handler triggered...");

    let db = DB::new(ctx.db());
    let agent = ctx
        .agent()
        .ok_or(CliError::AgentError(String::from("missing agent")))?;

    match commands {
        AccountCommands::GenerateDID { password } => {
            debug!(
                "[account:generateDID] agent from context: {}",
                ctx.agent().unwrap_or(String::from("empty agent"))
            );

            let method = build_rpc_method(Method::GenerateDID);
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<CoreAccountModel>();
            let resp = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::GenerateDID { password })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let rpc_resp = resp
                .result
                .ok_or(CliError::RpcError(String::from("missing result")))?;

            let did = rpc_resp.get_did();

            debug!("Saving DID Account...");
            let account = Account::new(
                rpc_resp.get_id(),
                DID::from(did.as_str()),
                rpc_resp.get_doc(),
            );

            let _ = db.save(AgentName::from(agent.as_str()), account);

            info!("Generated DID: {}", did);
        }

        AccountCommands::BuildDIDURI(args) => {
            println!("params: {:?}", args)
        }

        AccountCommands::ResolveDIDURI { uri } => {
            println!("uri: {}", uri)
        }

        AccountCommands::ResolveDIDDoc { uri } => {
            println!("uri: {}", uri)
        }

        AccountCommands::RemoveDID { did } => {
            debug!(
                "[account:removeDID] agent from context: {}",
                ctx.agent().unwrap_or(String::from("empty agent"))
            );

            debug!("[account:removeDID] DID: {did}");

            let method = build_rpc_method(Method::RemoveDID);
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<()>();
            
            let _ = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::RemoveDID { did: did.clone() })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;
            
            info!("DID: {did} has been removed")
        }

        AccountCommands::GetAccountDID { did } => {
            debug!(
                "[account:getAccountDID] agent from context: {}",
                ctx.agent().unwrap_or(String::from("empty agent"))
            );

            let method = build_rpc_method(Method::GetAccountDID);
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<CoreAccountModel>();
            let resp = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::GetAccountDID { did })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let rpc_resp = resp
                .result
                .ok_or(CliError::RpcError(String::from("missing result")))?;

            let jsonstr = serde_json::to_string_pretty(&rpc_resp)
                .map_err(|err| CliError::JSONError(err.to_string()))?;

            info!("Account JSON: {}", jsonstr)
        }
    }

    Ok(())
}

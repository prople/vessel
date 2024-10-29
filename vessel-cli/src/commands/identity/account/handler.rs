use rst_common::standard::serde_json;
use rst_common::with_logging::log::{debug, info};

use prople_did_core::did::query::Params as QueryParams;
use prople_did_core::doc::types::Doc;

use prople_jsonrpc_client::types::Executor;

use prople_vessel_core::identity::account::types::AccountEntityAccessor;
use prople_vessel_rpc::build_rpc_method;
use prople_vessel_rpc::components::account::{CoreAccountModel, Method, Param, ParamDomain};

use crate::commands::agents::get_agent_address;
use crate::commands::handler::ContextHandler;

use crate::models::db::DB;
use crate::models::identity::account::account::Account;
use crate::models::identity::account::accounts::Accounts;
use crate::models::identity::account::types::DID;
use crate::models::types::{AgentName, KeyIdentifier};

use crate::types::CliError;
use crate::utils::rpc::{build_client, http_to_multiaddr};

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

            let _ = db
                .save(AgentName::from(agent.clone()), account.clone())
                .await
                .map_err(|err| CliError::DBError(err.to_string()))?;

            debug!("Generate and saving accounts...");
            let accounts = Accounts::default();
            let accounts_key = accounts.key_name(AgentName::from(agent.clone()));

            let saved_accounts = db
                .get_model(accounts_key, |opt_val| match opt_val {
                    Some(val) => Accounts::try_from(val),
                    None => Ok(Accounts::default()),
                })
                .await
                .map_err(|err| CliError::DBError(err.to_string()))?;

            let _ = db
                .save(AgentName::from(agent), saved_accounts)
                .await
                .map_err(|err| CliError::DBError(err.to_string()))?;

            info!("Generated DID: {}", did);
        }

        AccountCommands::BuildDIDURI(args) => {
            debug!(
                "[account:buildDIDURI] agent from context: {}",
                ctx.agent().unwrap_or(String::from("empty agent"))
            );

            let method = build_rpc_method(Method::BuildDIDURI);
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<String>();

            let addr = http_to_multiaddr(args.address)?;
            debug!("Multiaddr format: {}", addr.to_string());

            let mut query_params = QueryParams::default();
            query_params.address = Some(addr.to_string());

            let resp = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::BuildDIDURI {
                        did: args.did,
                        password: args.password,
                        query_params: Some(query_params),
                    })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let rpc_resp = resp
                .result
                .ok_or(CliError::RpcError(String::from("missing result")))?;

            info!("Generated URI: {}", rpc_resp);
        }

        AccountCommands::ResolveDIDURI { uri } => {
            debug!(
                "[account:resolveDIDURI] agent from context: {}",
                ctx.agent().unwrap_or(String::from("empty agent"))
            );

            debug!("Given URI: {}", uri);

            let method = build_rpc_method(Method::ResolveDIDURI);
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<Doc>();

            let resp = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::ResolveDIDURI { uri })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let rpc_resp = resp
                .result
                .ok_or(CliError::RpcError(String::from("missing result")))?;

            let out = serde_json::to_string_pretty(&rpc_resp)
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            info!("Doc: \n{}", out)
        }

        AccountCommands::ResolveDIDDoc { did } => {
            debug!(
                "[account:resolveDIDDoc] agent from context: {}",
                ctx.agent().unwrap_or(String::from("empty agent"))
            );

            debug!("[account:resolveDIDDoc] did: {}", did);

            let method = build_rpc_method(Method::ResolveDIDDoc);
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<Doc>();

            let resp = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::ResolveDIDDoc { did })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let rpc_resp = resp
                .result
                .ok_or(CliError::RpcError(String::from("missing result")))?;

            let out = serde_json::to_string_pretty(&rpc_resp)
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            info!("Doc: \n{}", out)
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

            info!("Account JSON: \n{}", jsonstr)
        }
    }

    Ok(())
}

use prople_vessel_core::identity::verifiable::credential::types::CredentialEntityAccessor;
use rst_common::standard::serde_json;
use rst_common::with_logging::log::{debug, info};

use prople_jsonrpc_client::types::Executor;

use prople_vessel_rpc::build_rpc_method;
use prople_vessel_rpc::components::credential::{
    CoreCredentialModel, Method, MethodDomain, Param, ParamDomain,
};

use crate::commands::agents::get_agent_address;
use crate::commands::handler::ContextHandler;

use crate::models::identity::account::types::DID;
use crate::models::identity::verifiable::credential::Credential;
use crate::models::types::AgentName;

use crate::models::db::DB;
use crate::types::CliError;
use crate::utils::rpc::build_client;

use super::CredentialCommands;

pub async fn handle_commands(
    ctx: &ContextHandler,
    commands: CredentialCommands,
) -> Result<(), CliError> {
    debug!("account command handler triggered...");

    let db = DB::new(ctx.db());
    let agent = ctx
        .agent()
        .ok_or(CliError::AgentError(String::from("missing agent")))?;

    match commands {
        CredentialCommands::Generate(args) => {
            debug!(
                "[credential:generate] agent from context: {}",
                ctx.agent().unwrap_or(String::from("empty agent"))
            );

            let credential_value = serde_json::to_value(args.credential)
                .map_err(|err| CliError::JSONError(err.to_string()))?;

            let method = build_rpc_method(Method::Domain(MethodDomain::GenerateCredential));
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<CoreCredentialModel>();
            let resp = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::GenerateCredential {
                        password: args.password,
                        did_issuer: args.from_did,
                        credential: credential_value,
                    })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let rpc_resp = resp
                .result
                .ok_or(CliError::RpcError(String::from("missing result")))?;

            let credential = Credential::new(
                rpc_resp.get_id(),
                DID::from(rpc_resp.get_did_issuer().as_str()),
                rpc_resp.clone(),
            );
            
            let _ = db
                .save(AgentName::from(agent.clone()), credential.clone())
                .await
                .map_err(|err| CliError::DBError(err.to_string()))?;
            
            let out = serde_json::to_string_pretty(&rpc_resp)
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            info!("Credential generated successfully: {:?}", out);
        }
    }
    Ok(())
}

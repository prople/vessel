use cli_table::{print_stdout, WithTitle};

use rst_common::standard::serde_json;
use rst_common::with_logging::log::{debug, info};

use prople_did_core::did::query::Params as QueryParams;
use prople_jsonrpc_client::types::Executor;

use prople_vessel_core::identity::verifiable::credential::types::{
    CredentialEntityAccessor, HolderEntityAccessor,
};
use prople_vessel_core::identity::verifiable::types::PaginationParams;
use prople_vessel_rpc::build_rpc_method;
use prople_vessel_rpc::components::credential::{
    CoreCredentialModel, CoreHolderModel, Method, MethodDomain, Param, ParamDomain,
};

use crate::commands::agents::get_agent_address;
use crate::commands::handler::ContextHandler;

use crate::models::identity::account::types::DID;
use crate::models::identity::verifiable::credential::Credential;
use crate::models::types::AgentName;

use crate::models::db::DB;
use crate::types::CliError;
use crate::utils::rpc::{build_client, http_to_multiaddr};

use super::types::{CredentialWrapper, HolderWrapper};
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
        CredentialCommands::ListCredentialsByDID(args) => {
            let method = build_rpc_method(Method::Domain(MethodDomain::ListCredentialsByDID));
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<Vec<CoreCredentialModel>>();
            let pagination_params = PaginationParams {
                page: args.page.unwrap_or(0),
                limit: args.limit.unwrap_or(10),
                skip: 0,
            };

            let resp = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::ListCredentialsByDID {
                        did: args.did,
                        pagination_params: Some(pagination_params),
                    })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let rpc_resp = resp
                .result
                .ok_or(CliError::RpcError(String::from("missing result")))?;

            let credential_list: Vec<CredentialWrapper> = rpc_resp
                .iter()
                .map(|credential| {
                    let mut did_vc = credential.get_did_vc();
                    did_vc.truncate(did_vc.len() / 2);
                    did_vc.push_str("...");

                    CredentialWrapper {
                        id: credential.get_id(),
                        did_vc,
                        created_at: credential.get_created_at(),
                        updated_at: credential.get_updated_at(),
                    }
                })
                .collect();

            let _ = print_stdout(credential_list.with_title())
                .map_err(|err| CliError::AgentError(err.to_string()))?;
        }
        CredentialCommands::ListCredentialsIds(args) => {
            let method = build_rpc_method(Method::Domain(MethodDomain::ListCredentialsByIDs));
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<Vec<CoreCredentialModel>>();

            let resp = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::ListCredentialsByIDs {
                        ids: args.ids,
                    })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let rpc_resp = resp
                .result
                .ok_or(CliError::RpcError(String::from("missing result")))?;

            let credential_list: Vec<CredentialWrapper> = rpc_resp
                .iter()
                .map(|credential| {
                    let mut did_vc = credential.get_did_vc();
                    did_vc.truncate(did_vc.len() / 2);
                    did_vc.push_str("...");

                    CredentialWrapper {
                        id: credential.get_id(),
                        did_vc,
                        created_at: credential.get_created_at(),
                        updated_at: credential.get_updated_at(),
                    }
                })
                .collect();

            let _ = print_stdout(credential_list.with_title())
                .map_err(|err| CliError::AgentError(err.to_string()))?;
        }
        CredentialCommands::Send(args) => {
            let method = build_rpc_method(Method::Domain(MethodDomain::SendCredential));
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<()>();

            let addr = http_to_multiaddr(args.address)?;
            debug!("Multiaddr format: {}", addr.to_string());

            let mut query_params = QueryParams::default();
            query_params.address = Some(addr.to_string());

            let _ = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::SendCredential {
                        password: args.password,
                        did_uri: args.to_did,
                        id: args.credential_id,
                        params: Some(query_params),
                    })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            info!("Credential sent successfully");
        }
        CredentialCommands::ListHoldersByDID(args) => {
            let method = build_rpc_method(Method::Domain(MethodDomain::ListHoldersByDID));
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<Vec<CoreHolderModel>>();
            let pagination_params = PaginationParams {
                page: args.page.unwrap_or(0),
                limit: args.limit.unwrap_or(10),
                skip: 0,
            };

            let resp = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::ListHoldersByDID {
                        did: args.did,
                        pagination_params: Some(pagination_params),
                    })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let rpc_resp = resp
                .result
                .ok_or(CliError::RpcError(String::from("missing result")))?;

            let holder_list: Vec<HolderWrapper> = rpc_resp
                .iter()
                .map(|holder| {
                    let mut did_vc = holder.get_vc().id;
                    did_vc.truncate(did_vc.len() / 5);
                    did_vc.push_str("...");

                    let mut did_holder = holder.get_did_holder();
                    did_holder.truncate(did_holder.len() / 3);
                    did_holder.push_str("...");

                    HolderWrapper {
                        id: holder.get_id(),
                        vc: did_vc,
                        did_holder,
                        created_at: holder.get_created_at(),
                        updated_at: holder.get_updated_at(),
                    }
                })
                .collect();

            let _ = print_stdout(holder_list.with_title())
                .map_err(|err| CliError::AgentError(err.to_string()))?;
        }
        CredentialCommands::ListHoldersIds(args) => {
            let method = build_rpc_method(Method::Domain(MethodDomain::ListHoldersByIDs));
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<Vec<CoreHolderModel>>();

            let resp = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::ListHoldersByIDs {
                        ids: args.ids,
                    })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let rpc_resp = resp
                .result
                .ok_or(CliError::RpcError(String::from("missing result")))?;

            let holder_list: Vec<HolderWrapper> = rpc_resp
                .iter()
                .map(|holder| {
                    let mut did_vc = holder.get_vc().id;
                    did_vc.truncate(did_vc.len() / 5);
                    did_vc.push_str("...");

                    let mut did_holder = holder.get_did_holder();
                    did_holder.truncate(did_holder.len() / 3);
                    did_holder.push_str("...");

                    HolderWrapper {
                        id: holder.get_id(),
                        vc: did_vc,
                        did_holder,
                        created_at: holder.get_created_at(),
                        updated_at: holder.get_updated_at(),
                    }
                })
                .collect();

            let _ = print_stdout(holder_list.with_title())
                .map_err(|err| CliError::AgentError(err.to_string()))?;
        }
    }
    Ok(())
}

use cli_table::{print_stdout, WithTitle};
use formatjson::format_json;

use rst_common::with_logging::log::{debug, info};
use rstdev_domain::entity::ToJSON;

use prople_did_core::did::query::Params as QueryParams;
use prople_jsonrpc_client::types::Executor;
use prople_vessel_core::identity::verifiable::presentation::types::{
    PresentationEntityAccessor, VerifierEntityAccessor,
};

use prople_vessel_rpc::components::presentation::{
    CorePresentationModel, CoreVerifierModel, Method, MethodDomain, Param, ParamDomain,
};

use prople_vessel_rpc::build_rpc_method;

use crate::commands::agents::get_agent_address;
use crate::commands::handler::ContextHandler;

use crate::models::db::DB;
use crate::models::identity::account::types::DID;
use crate::models::identity::verifiable::presentation::Presentation;
use crate::models::types::AgentName;

use crate::types::CliError;
use crate::utils::rpc::{build_client, http_to_multiaddr};

use super::types::VerifierWrapper;
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
                        holders: args.holders,
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

            info!(
                "Presentation generated successfully: PresentationID: {}",
                rpc_resp.get_id()
            );
        }
        PresentationCommands::Send(args) => {
            debug!(
                "[presentation:send] agent from context: {}",
                ctx.agent().unwrap_or(String::from("empty agent"))
            );

            let method = build_rpc_method(Method::Domain(MethodDomain::SendPresentation));
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<()>();

            let addr = http_to_multiaddr(args.address)?;
            debug!("Multiaddr format: {}", addr.to_string());

            let mut query_params = QueryParams::default();
            query_params.address = Some(addr.to_string());

            let _ = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::SendPresentation {
                        id: args.presentation_id,
                        did_uri: args.to_did,
                        password: args.password,
                        params: Some(query_params),
                    })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            info!("Presentation sent successfully");
        }
        PresentationCommands::ListVerifiersByDID(args) => {
            debug!(
                "[presentation:list_verifiers_by_did] agent from context: {}",
                ctx.agent().unwrap_or(String::from("empty agent"))
            );

            let method = build_rpc_method(Method::Domain(MethodDomain::ListVerifiersByDID));
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<Vec<CoreVerifierModel>>();

            let resp = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::ListVPsByDIDVerifier {
                        did_verifier: args.did,
                    })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let rpc_resp = resp
                .result
                .ok_or(CliError::RpcError(String::from("missing result")))?;

            let verifier_list: Vec<VerifierWrapper> = rpc_resp
                .iter()
                .map(|verifier| {
                    let mut did_verifier = verifier.get_did_verifier();
                    did_verifier.truncate(did_verifier.len() / 2);
                    did_verifier.push_str("...");

                    VerifierWrapper {
                        id: verifier.get_id(),
                        did_verifier,
                        created_at: verifier.get_created_at(),
                        updated_at: verifier.get_updated_at(),
                    }
                })
                .collect();

            let _ = print_stdout(verifier_list.with_title())
                .map_err(|err| CliError::AgentError(err.to_string()))?;
        }
        PresentationCommands::Verify(args) => {
            debug!(
                "[presentation:verify] agent from context: {}",
                ctx.agent().unwrap_or(String::from("empty agent"))
            );

            let method = build_rpc_method(Method::Domain(MethodDomain::VerifyPresentation));
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<()>();

            let _ = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::VerifyPresentation {
                        id: args.id,
                    })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            info!("Presentation verified successfully");
        }
        PresentationCommands::GetPresentationByID { id } => {
            debug!(
                "[presentation:get_presentation_by_id] agent from context: {}",
                ctx.agent().unwrap_or(String::from("empty agent"))
            );

            let method = build_rpc_method(Method::Domain(MethodDomain::GetByID));
            let agent_addr = get_agent_address(ctx)?;
            let client = build_client::<CorePresentationModel>();

            let resp = client
                .call(
                    agent_addr,
                    Some(Param::Domain(ParamDomain::GetByID { id })),
                    method.to_string(),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let rpc_resp = resp
                .result
                .ok_or(CliError::RpcError(String::from("missing result")))?;

            let presentation_json = rpc_resp
                .to_json()
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let formatted_json = format_json(&presentation_json)
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            info!("Presentation retrieved successfully: {}", formatted_json);
        }
    }
    Ok(())
}

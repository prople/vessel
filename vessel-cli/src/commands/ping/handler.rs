use rst_common::standard::serde_json;
use rst_common::with_logging::log::{debug, info};

use prople_jsonrpc_client::types::Executor;
use prople_jsonrpc_client::types::NullValue;
use prople_jsonrpc_core::handlers::{AgentPingResponse, PING_RPC_METHOD};

use crate::commands::agents::get_agent_address;
use crate::commands::handler::ContextHandler;
use crate::types::CliError;
use crate::utils::rpc::build_client;

use super::PingCommands;

pub async fn handle_commands(ctx: &ContextHandler, commands: PingCommands) -> Result<(), CliError> {
    debug!("ping command handler triggered...");

    match commands {
        PingCommands::Agent => {
            debug!(
                "[ping] agent from context: {}",
                ctx.agent().unwrap_or(String::from("empty agent"))
            );

            let agent_addr = get_agent_address(ctx)?;

            let client = build_client::<AgentPingResponse>();
            let resp = client
                .call(
                    agent_addr,
                    None::<NullValue>,
                    String::from(PING_RPC_METHOD),
                    None,
                )
                .await
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            let rpc_resp = resp
                .result
                .ok_or(CliError::RpcError(String::from("missing result")))?;

            let rpc_resp_json = serde_json::to_string(&rpc_resp)
                .map_err(|err| CliError::RpcError(err.to_string()))?;

            info!("[agent:ping] response: {}", rpc_resp_json)
        }
    }

    Ok(())
}

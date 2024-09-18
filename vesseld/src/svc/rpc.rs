use std::time::Duration;

use rst_common::with_http_tokio::axum::routing::post;
use rst_common::with_http_tokio::axum::Router;
use rst_common::with_http_tokio::tower_http::timeout::TimeoutLayer;
use rst_common::with_http_tokio::tower_http::trace::TraceLayer;
use rst_common::with_tracing::tracing_subscriber::{
    self, layer::SubscriberExt, util::SubscriberInitExt,
};

use prople_jsonrpc_axum::rpc::{Rpc as RpcAxum, RpcConfig, RpcError, RpcHandlerFn, RpcState};
use prople_vessel_rpc::VesselRPC;

pub struct Rpc {
    config: String,
}

impl Rpc {
    pub fn new(config: String) -> Rpc {
        Self { config }
    }

    pub fn svc(&self) -> Result<RpcAxum, RpcError> {
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                    format!(
                        "{}=debug,tower_http=debug,axum=trace",
                        env!("CARGO_CRATE_NAME")
                    )
                    .into()
                }),
            )
            .with(tracing_subscriber::fmt::layer().without_time())
            .init();

        let mut vessel_rpc =
            VesselRPC::new(&self.config).map_err(|err| RpcError::AxumError(err.to_string()))?;

        let config_app = vessel_rpc
            .build_app_config()
            .map_err(|err| RpcError::AxumError(err.to_string()))?;

        let rpc_identity = vessel_rpc
            .build_rpc_identity()
            .map_err(|err| RpcError::AxumError(err.to_string()))?;

        let rpc_state = RpcState::new(rpc_identity.processor());
        let rpc_app = Router::new().route("/rpc", post(RpcHandlerFn)).layer((
            TraceLayer::new_for_http(),
            TimeoutLayer::new(Duration::from_secs(10)),
        ));

        let (host, port) = config_app.get_app_config();
        let axum_config = RpcConfig::new(host, port);

        Ok(RpcAxum::new(axum_config, rpc_state, rpc_app))
    }
}

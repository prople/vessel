use std::time::Duration;

use rst_common::with_http_tokio::axum::routing::post;
use rst_common::with_http_tokio::axum::Router;
use rst_common::with_http_tokio::tower_http::timeout::TimeoutLayer;
use rst_common::with_http_tokio::tower_http::trace::TraceLayer;
use rst_common::with_tracing::tracing;
use rst_common::with_tracing::tracing_subscriber::filter::Directive;
use rst_common::with_tracing::tracing_subscriber::{
    self, filter::LevelFilter, fmt, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter,
};

use prople_jsonrpc_axum::rpc::{Rpc as RpcAxum, RpcConfig, RpcError, RpcHandlerFn, RpcState};
use prople_vessel_rpc::VesselRPC;

pub struct Rpc {
    config: String,
    enable_debug: bool,
}

impl Rpc {
    pub fn new(config: String, enable_debug: bool) -> Rpc {
        Self {
            config,
            enable_debug,
        }
    }

    pub fn svc(&self) -> Result<RpcAxum, RpcError> {
        let mut default_log_level: Directive = LevelFilter::INFO.into();
        if self.enable_debug {
            default_log_level = LevelFilter::DEBUG.into();
        }

        let env_filter = EnvFilter::builder()
            .with_default_directive(default_log_level.clone())
            .parse("")
            .map_err(|err| RpcError::AxumError(err.to_string()))?;

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt::layer().without_time())
            .init();

        tracing::info!("Log level: {}", default_log_level.to_string());

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

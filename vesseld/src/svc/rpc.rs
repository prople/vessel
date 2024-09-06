use std::sync::Arc;
use std::time::Duration;

use rst_common::standard::erased_serde::Serialize as ErasedSerialized;
use rst_common::with_http_tokio::axum::extract::{Json, State};
use rst_common::with_http_tokio::axum::http::StatusCode;
use rst_common::with_http_tokio::axum::routing::post;
use rst_common::with_http_tokio::axum::{self, Router};
use rst_common::with_http_tokio::tower_http::timeout::TimeoutLayer;
use rst_common::with_http_tokio::tower_http::trace::TraceLayer;
use rst_common::with_tokio::tokio::net::TcpListener;
use rst_common::with_tokio::tokio::{self, signal};
use rst_common::with_tracing::tracing;
use rst_common::with_tracing::tracing_subscriber::{
    self, layer::SubscriberExt, util::SubscriberInitExt,
};

use prople_jsonrpc_core::objects::{RpcProcessor, RpcRequest, RpcResponse};
use prople_jsonrpc_core::types::*;
use prople_vessel_rpc::{ConfigApp, VesselRPC};

use crate::errors::VesselError;

#[derive(Clone)]
pub struct RpcState {
    processor: Arc<RpcProcessor>,
}

impl RpcState {
    pub fn new(processor: RpcProcessor) -> Self {
        Self {
            processor: Arc::new(processor),
        }
    }
}

async fn rpc_handler(
    State(state): State<Arc<RpcState>>,
    Json(payload): Json<RpcRequest>,
) -> (StatusCode, Json<RpcResponse<Box<dyn ErasedSerialized>, ()>>) {
    let processor = state.processor.clone();
    let response = processor.execute(payload).await;

    let err = response.error.clone();
    let status_code = err
        .clone()
        .map(|err_obj| err_obj.code)
        .map(|err_code| match err_code {
            INVALID_REQUEST_CODE | INVALID_PARAMS_CODE | PARSE_ERROR_CODE => {
                StatusCode::BAD_REQUEST
            }
            METHOD_NOT_FOUND_CODE => StatusCode::NOT_FOUND,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        })
        .unwrap_or_else(|| StatusCode::OK);

    (status_code, Json(response))
}

pub struct Svc {
    config_app: ConfigApp,
    state: RpcState,
    svc_app: Router<Arc<RpcState>>,
}

impl Svc {
    pub fn new(config_app: ConfigApp, state: RpcState, svc_app: Router<Arc<RpcState>>) -> Self {
        Self {
            config_app,
            state,
            svc_app,
        }
    }

    pub async fn serve(&self) -> Result<(), VesselError> {
        let (host, port) = self.config_app.get_app_config();
        tracing::info!("listening at: host:{} | port:{}", host, port);

        let listener = TcpListener::bind(format!("{}:{}", host, port))
            .await
            .map_err(|err| VesselError::RpcError(err.to_string()))?;

        let app = self
            .svc_app
            .clone()
            .with_state(Arc::new(self.state.clone()));

        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let ctrl_c = async { signal::ctrl_c().await.expect("error Ctrl-C handler") };

                #[cfg(unix)]
                let terminate = async {
                    signal::unix::signal(signal::unix::SignalKind::terminate())
                        .expect("failed to install signal handler")
                        .recv()
                        .await;
                };

                #[cfg(not(unix))]
                let terminate = std::future::pending::<()>();

                tokio::select! {
                    _ = ctrl_c => {},
                    _ = terminate => {},
                }
            })
            .await
            .map_err(|err| VesselError::RpcError(err.to_string()))?;

        Ok(())
    }
}

pub struct Rpc {
    config: String,
}

impl Rpc {
    pub fn new(config: String) -> Rpc {
        Self { config }
    }

    pub fn svc(&self) -> Result<Svc, VesselError> {
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
            VesselRPC::new(&self.config).map_err(|err| VesselError::RpcError(err.to_string()))?;

        let config_app = vessel_rpc
            .build_app_config()
            .map_err(|err| VesselError::RpcError(err.to_string()))?;

        let rpc_identity = vessel_rpc
            .build_rpc_identity()
            .map_err(|err| VesselError::RpcError(err.to_string()))?;

        let rpc_state = RpcState::new(rpc_identity.processor());
        let rpc_app = Router::new().route("/rpc", post(rpc_handler)).layer((
            TraceLayer::new_for_http(),
            TimeoutLayer::new(Duration::from_secs(10)),
        ));

        Ok(Svc::new(config_app, rpc_state, rpc_app))
    }
}

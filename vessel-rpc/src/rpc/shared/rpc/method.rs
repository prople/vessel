use prople_jsonrpc_core::types::RpcMethod;

pub const RPC_METHOD_PREFIX: &str = "prople.vessel";

pub trait RpcMethodBuilder {
    fn build_path(&self) -> &str;
}

pub fn build_rpc_method(method: impl RpcMethodBuilder) -> RpcMethod {
    RpcMethod::from(format!("{}.{}", RPC_METHOD_PREFIX, method.build_path()))
}

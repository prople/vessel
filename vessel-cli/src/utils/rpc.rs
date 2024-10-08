use std::fmt::Debug;

use rst_common::standard::serde::de::DeserializeOwned;

use prople_jsonrpc_client::executor::reqwest::Reqwest;
use prople_jsonrpc_client::types::Executor;

pub fn build_client<TResp>() -> impl Executor<TResp>
where
    TResp: DeserializeOwned + Clone + Send + Sync + Debug,
{
    Reqwest::<TResp>::new()
}

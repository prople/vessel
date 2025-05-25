use cli_table::Table;

use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};

#[derive(Serialize, Deserialize, Table, Clone)]
#[serde(crate = "self::serde")]
pub(crate) struct CredentialWrapper {
    #[table(title = "id")]
    pub(crate) id: String,

    #[table(title = "DID VC")]
    pub(crate) did_vc: String,

    #[table(title = "Created At")]
    #[serde(with = "ts_seconds")]
    #[serde(rename = "createdAt")]
    pub(crate) created_at: DateTime<Utc>,

    #[table(title = "Updated At")]
    #[serde(with = "ts_seconds")]
    #[serde(rename = "updatedAt")]
    pub(crate) updated_at: DateTime<Utc>,
}

#[derive(Serialize, Deserialize, Table, Clone)]
#[serde(crate = "self::serde")]
pub(crate) struct HolderWrapper {
    pub(crate) id: String,
    pub(crate) did_holder: String,
    pub(crate) vc: String,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "createdAt")]
    pub(crate) created_at: DateTime<Utc>,

    #[serde(with = "ts_seconds")]
    #[serde(rename = "updatedAt")]
    pub(crate) updated_at: DateTime<Utc>,
}

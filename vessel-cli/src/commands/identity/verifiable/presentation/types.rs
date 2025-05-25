use cli_table::Table;

use rst_common::standard::chrono::serde::ts_seconds;
use rst_common::standard::chrono::{DateTime, Utc};
use rst_common::standard::serde::{self, Deserialize, Serialize};

#[derive(Serialize, Deserialize, Table, Clone)]
#[serde(crate = "self::serde")]
pub(crate) struct VerifierWrapper {
    #[table(title = "id")]
    pub(crate) id: String,

    #[table(title = "DID Verifier")]
    pub(crate) did_verifier: String,

    #[table(title = "Created At")]
    #[serde(with = "ts_seconds")]
    #[serde(rename = "createdAt")]
    pub(crate) created_at: DateTime<Utc>,

    #[table(title = "Updated At")]
    #[serde(with = "ts_seconds")]
    #[serde(rename = "updatedAt")]
    pub(crate) updated_at: DateTime<Utc>,
}

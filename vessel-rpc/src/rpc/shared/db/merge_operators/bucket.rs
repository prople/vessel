use rst_common::standard::serde::de::DeserializeOwned;
use rst_common::standard::serde::Serialize;

use rstdev_storage::engine::rocksdb::lib::rust_rocksdb::merge_operator::MergeOperands;

use prople_vessel_core::identity::verifiable::credential::types::CredentialError;
use prople_vessel_core::identity::verifiable::Credential;

use prople_vessel_core::identity::verifiable::presentation::types::PresentationError;
use prople_vessel_core::identity::verifiable::presentation::Verifier;

use crate::rpc::shared::db::{Bucket as DbBucket, DbError};

pub const MERGE_BUCKET_ID: &str = "merge_bucket";

fn merge_bucket_builder<T: TryInto<Vec<u8>> + Serialize + DeserializeOwned>(
    existing: Option<&[u8]>,
) -> Option<DbBucket<T>> {
    let bucket = {
        existing.map_or_else(
            || {
                let bucket: DbBucket<T> = DbBucket::new();
                Some(bucket)
            },
            |val| {
                let bin_builder: Result<DbBucket<T>, DbError> = val.to_vec().try_into();
                match bin_builder {
                    Ok(bucket) => Some(bucket),
                    Err(_) => None,
                }
            },
        )
    }?;

    Some(bucket)
}

fn merge_bucket_credential(existing: Option<&[u8]>, operands: &MergeOperands) -> Option<Vec<u8>> {
    let mut bucket: DbBucket<Credential> = merge_bucket_builder(existing)?;
    for op in operands {
        let op_credential = {
            let credential_builder: Result<Credential, CredentialError> = op.to_vec().try_into();
            match credential_builder {
                Ok(credential) => Some(credential),
                Err(_) => None,
            }
        };

        op_credential.map(|cred| {
            bucket.add(cred);
        });
    }

    let output = {
        let bucket_bin_builder: Result<Vec<u8>, DbError> = bucket.try_into();
        match bucket_bin_builder {
            Ok(bin) => Some(bin),
            Err(_) => None,
        }
    };

    output
}

fn merge_bucket_presentation(existing: Option<&[u8]>, operands: &MergeOperands) -> Option<Vec<u8>> {
    let mut bucket: DbBucket<Verifier> = merge_bucket_builder(existing)?;

    for op in operands {
        let op_presentation = {
            let presentation_builder: Result<Verifier, PresentationError> = op.to_vec().try_into();

            match presentation_builder {
                Ok(presentation) => Some(presentation),
                Err(_) => None,
            }
        };

        op_presentation.map(|presentation| {
            bucket.add(presentation);
        });
    }

    let output = {
        let bucket_bin_builder: Result<Vec<u8>, DbError> = bucket.try_into();
        match bucket_bin_builder {
            Ok(bin) => Some(bin),
            Err(_) => None,
        }
    };

    output
}

pub fn merge_bucket(
    new_key: &[u8],
    existing: Option<&[u8]>,
    operands: &MergeOperands,
) -> Option<Vec<u8>> {
    let allowed_keys = vec!["merge_credential", "merge_presentation"];

    let key = {
        match String::from_utf8(new_key.to_vec()) {
            Ok(key_val) => Some(key_val),
            Err(_) => None,
        }
    }
    .filter(|key| {
        let mut selected_key = String::from("");
        for allowed in allowed_keys.iter() {
            if key.as_str().contains(*allowed) {
                selected_key = allowed.to_string();
                break;
            }
        }

        !selected_key.is_empty()
    });

    if key.is_none() {
        let existing_val = existing.map(|val| val.to_vec())?;
        return Some(existing_val);
    }

    let output = {
        match key {
            Some(key) => {
                let mut str_splitted = key.as_str().split(":");
                let first_index = str_splitted.next();
                match first_index {
                    Some("merge_credential") => {
                        let output = merge_bucket_credential(existing, operands);
                        output
                    }
                    Some("merge_presentation") => {
                        let output = merge_bucket_presentation(existing, operands);
                        output
                    }
                    _ => None,
                }
            }
            None => None,
        }
    };

    output
}

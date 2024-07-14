use rstdev_storage::engine::rocksdb::lib::rust_rocksdb::merge_operator::MergeOperands;

use prople_vessel_core::identity::verifiable::credential::types::CredentialError;
use prople_vessel_core::identity::verifiable::Credential;

use crate::apps::db::{Bucket, DbError};

pub const MERGE_BUCKET_CREDENTIAL_ID: &str = "merge_bucket_credential";

pub fn merge_bucket_credential(
    new_key: &[u8],
    existing: Option<&[u8]>,
    operands: &MergeOperands,
) -> Option<Vec<u8>> {
    let key = {
        match String::from_utf8(new_key.to_vec()) {
            Ok(key_val) => Some(key_val),
            Err(_) => None,
        }
    }
    .filter(|key| {
        let prefix = "merge_credential";
        key.as_str().contains(prefix)
    });

    if key.is_none() {
        let existing_val = existing.map(|val| val.to_vec())?;
        return Some(existing_val);
    }

    let mut bucket = {
        existing.map_or_else(
            || {
                let bucket: Bucket<Credential> = Bucket::new();
                Some(bucket)
            },
            |val| {
                let bin_builder: Result<Bucket<Credential>, DbError> = val.to_vec().try_into();
                match bin_builder {
                    Ok(bucket) => Some(bucket),
                    Err(_) => None,
                }
            },
        )
    }?;

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

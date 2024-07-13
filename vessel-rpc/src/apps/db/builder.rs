use rstdev_storage::engine::rocksdb::db::DB;
use rstdev_storage::engine::rocksdb::options::Options;
use rstdev_storage::engine::rocksdb::rocksdb::rust_rocksdb::merge_operator::MergeOperands;

use prople_vessel_core::identity::verifiable::credential::types::CredentialError;
use prople_vessel_core::identity::verifiable::Credential;

use crate::common::types::CommonError;
use crate::config::{RocksDBCommon, RocksDBOptions};
use crate::Config;

use super::{Bucket, DbError, Runner};

fn merge_bucket_credential(
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

pub struct Builder {
    cfg: Config,
}

impl Builder {
    pub fn new(cfg: Config) -> Self {
        Self { cfg }
    }

    pub fn build<'a>(
        &'a mut self,
        db_callback: impl FnOnce(&Config) -> (RocksDBCommon, RocksDBOptions),
    ) -> Result<Runner<DB>, CommonError> {
        let (opts_common, opts_db) = db_callback(&self.cfg);
        let (opts_path, opts_cf_name) = opts_common.get();

        let opts_db_main = opts_db.clone();

        let mut db_opts = Options::new(opts_path, opts_cf_name);
        db_opts.build_default_opts().set_db_opts(move |opt| {
            opt.create_if_missing(opts_db_main.get_create_if_missing());
            opt.create_missing_column_families(opts_db_main.get_create_missing_columns());
            opt.set_error_if_exists(opts_db_main.get_set_error_if_exists());
            opt.set_wal_dir(opts_db_main.get_set_wal_dir());

            opt
        }).set_cf_opts(|opt| {
            opt.set_merge_operator_associative("merge bucket credential", merge_bucket_credential);

            opt
        });

        let mut db = DB::new(db_opts).map_err(|err| CommonError::DBError(err.to_string()))?;
        let _ = db
            .build()
            .map_err(|err| CommonError::DBError(err.to_string()))?;

        Ok(Runner::new(db, self.cfg.to_owned()))
    }
}

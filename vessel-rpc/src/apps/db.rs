use std::sync::Arc;

use rstdev_storage::engine::rocksdb::db::DB;
use rstdev_storage::engine::rocksdb::options::Options;
use rstdev_storage::types::Storage;

use crate::common::types::CommonError;
use crate::config::{RocksDBCommon, RocksDBOptions};
use crate::Config;

pub type RocksDBStorageInstance = Option<Box<dyn Storage<Instance = Arc<DB>>>>;

pub struct Builder {
    cfg: Config,
    pub(crate) instance: RocksDBStorageInstance,
}

impl Builder {
    pub fn new(cfg: Config) -> Self {
        Self {
            cfg,
            instance: None,
        }
    }

    pub fn build(
        &mut self,
        db_callback: impl FnOnce(&Config) -> (RocksDBCommon, RocksDBOptions),
    ) -> Result<(), CommonError> {
        let (opts_common, opts_db) = db_callback(&self.cfg);
        let (opts_path, opts_cf_name) = opts_common.get();

        let opts_db_main = opts_db.clone();

        let mut db_opts = Options::new(opts_path, opts_cf_name);
        db_opts
            .build_default_opts()
            .set_db_opts(move |opt| {
                opt.create_if_missing(opts_db_main.get_create_if_missing());
                opt.create_missing_column_families(opts_db_main.get_create_missing_columns());
                opt.set_error_if_exists(opts_db_main.get_set_error_if_exists());
                opt.set_wal_dir(opts_db_main.get_set_wal_dir());

                opt
            });

        let mut db = DB::new(db_opts).map_err(|err| CommonError::DBError(err.to_string()))?;
        let _ = db
            .build()
            .map_err(|err| CommonError::DBError(err.to_string()))?;

        self.instance = Some(Box::new(db));

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    use std::env;
    use std::path::PathBuf;

    use crate::ConfigManager;

    #[test]
    fn test_build_db() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src/config/fixtures");
        
        let toml_file = format!("{}/config.toml", path.display());
        let config_parser = ConfigManager::new(toml_file);
        let config_builder = config_parser.parse();
        assert!(!config_builder.is_err());

        let config = config_builder.unwrap();
        let mut db_builder = Builder::new(config);

        let db_builder_build = db_builder.build(|opts| {
            let opts_db = opts.db();
            let opts_db_identity = opts_db.identity.clone();

            let opts_db_common = opts_db_identity.clone().get_common().clone();
            let opts_db_main = opts_db_identity.clone().get_db_options().clone();

            (opts_db_common, opts_db_main)
        });

        assert!(!db_builder_build.is_err())
    }
}
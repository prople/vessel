use super::types::{CommonError, ToValidate};

pub fn validate(validator: impl ToValidate) -> Result<(), CommonError> {
    validator.validate()
}

#[cfg(test)]
pub mod testdb {

    use once_cell::sync::OnceCell;
    use std::env;
    use std::path::PathBuf;

    use rstdev_storage::engine::rocksdb::executor::Executor;

    use crate::ConfigManager;
    use crate::DbBuilder;

    pub fn global_db_parser() -> &'static ConfigManager {
        static INSTANCE: OnceCell<ConfigManager> = OnceCell::new();
        INSTANCE.get_or_init(|| {
            let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            path.push("src/config/fixtures");

            let toml_file = format!("{}/config.toml", path.display());
            let config_parser = ConfigManager::new(toml_file);

            config_parser
        })
    }

    pub fn global_db_builder() -> &'static Executor {
        static INSTANCE: OnceCell<Executor> = OnceCell::new();
        INSTANCE.get_or_init(|| {
            let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
            path.push("src/config/fixtures");

            let toml_file = format!("{}/config.toml", path.display());
            let config_parser = ConfigManager::new(toml_file);
            let config = config_parser.parse().unwrap();

            let mut db_builder = DbBuilder::new(config);
            let runner = db_builder
                .build(|opts| {
                    let opts_db = opts.db();
                    let opts_db_identity = opts_db.identity.clone();

                    let opts_db_common = opts_db_identity.clone().get_common().clone();
                    let opts_db_main = opts_db_identity.clone().get_db_options().clone();

                    (opts_db_common, opts_db_main)
                })
                .unwrap();

            runner
        })
    }
}

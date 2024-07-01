use rst_common::standard::serde::{self, Deserialize};

#[derive(Deserialize, Debug)]
#[serde(crate = "self::serde")]
pub struct RocksDBCommon {
    pub(super) path: String,
    pub(super) cf_name: String,
}

impl RocksDBCommon {
    pub fn get(&self) -> (String, String) {
        (self.path.to_owned(), self.cf_name.to_owned())
    }
}

impl Default for RocksDBCommon {
    fn default() -> Self {
        Self {
            path: "./db".to_string(),
            cf_name: "".to_string(),
        }
    }
}

#[derive(Deserialize, Clone, Debug)]
#[serde(crate = "self::serde")]
pub struct RocksDBOptions {
    pub(super) create_if_missing: bool,
    pub(super) create_missing_columns: bool,
    pub(super) set_error_if_missing: bool,
    pub(super) set_wal_dir: String,
}

impl RocksDBOptions {
    pub fn get_create_if_missing(&self) -> bool {
        self.create_if_missing.to_owned()
    }

    pub fn get_create_missing_columns(&self) -> bool {
        self.create_missing_columns.to_owned()
    }

    pub fn get_set_error_if_missing(&self) -> bool {
        self.set_error_if_missing.to_owned()
    }

    pub fn get_set_wal_dir(&self) -> String {
        self.set_wal_dir.to_owned()
    }
}

impl Default for RocksDBOptions {
    fn default() -> Self {
        Self {
            create_if_missing: true,
            create_missing_columns: true,
            set_error_if_missing: false,
            set_wal_dir: "".to_string(),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(crate = "self::serde")]
pub struct Database {
    pub identity: Identity,
}

impl Default for Database {
    fn default() -> Self {
        Self {
            identity: Identity::default(),
        }
    }
}

#[derive(Deserialize, Debug)]
#[serde(crate = "self::serde")]
pub struct Identity {
    pub(super) common: RocksDBCommon,
    pub(super) db: RocksDBOptions,
}

impl Identity {
    pub fn get_common(&self) -> (String, String) {
        self.common.get()
    }

    pub fn get_db_options(&self) -> RocksDBOptions {
        self.db.to_owned()
    }
}

impl Default for Identity {
    fn default() -> Self {
        Self {
            common: RocksDBCommon::default(),
            db: RocksDBOptions::default(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::PathBuf;

    use rstdev_config::format::use_toml;
    use rstdev_config::parser::from_file;
    use rstdev_config::{types::ConfigError, Builder};

    #[test]
    fn test_parse_databae_config() -> Result<(), ConfigError> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src/config/fixtures");

        let toml_file = format!("{}/config_db.toml", path.display());
        let config_toml = {
            let config_builder: Result<Database, ConfigError> =
                Builder::new(from_file(toml_file)).fetch()?.parse(use_toml);

            config_builder
        };

        assert!(!config_toml.is_err());

        let config_db = config_toml.unwrap();
        assert_eq!(config_db.identity.common.cf_name, "identity-cf");
        assert_eq!(config_db.identity.common.path, "./identity-storage");
        assert_eq!(config_db.identity.db.set_wal_dir, "./identity-db-wall");

        assert!(config_db.identity.db.create_if_missing);
        assert!(config_db.identity.db.create_missing_columns);
        assert!(config_db.identity.db.set_error_if_missing);
        Ok(())
    }
}

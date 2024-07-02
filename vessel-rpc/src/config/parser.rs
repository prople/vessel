use rstdev_config::format::use_toml;
use rstdev_config::parser::from_file;
use rstdev_config::{types::ConfigError, Builder};

use super::Config;

pub struct Parser {
    conf_file: String,
}

impl Parser {
    pub fn new(conf_file: String) -> Self {
        Self { conf_file }
    }

    pub fn parse(&self) -> Result<Config, ConfigError> {
        let config_toml = {
            let config_builder: Result<Config, ConfigError> =
                Builder::new(from_file(self.conf_file.to_owned()))
                    .fetch()?
                    .parse(use_toml);

            config_builder
        };

        config_toml
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;
    use std::path::PathBuf;

    #[test]
    fn test_parse_config() {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src/config/fixtures");

        let toml_file = format!("{}/config.toml", path.display());
        let parser = Parser::new(toml_file);
        let config_builder = parser.parse();

        assert!(!config_builder.is_err());

        let config_app = config_builder.as_ref().unwrap().app();
        let (host, port) = config_app.get_app_config();
        assert_eq!("localhost".to_string(), host);
        assert_eq!("8181".to_string(), port);

        let config_db = config_builder.as_ref().unwrap().db();

        let (dbpath, cfname) = config_db.identity.get_common().get();
        assert_eq!("./identity-storage".to_string(), dbpath);
        assert_eq!("identity-cf".to_string(), cfname);

        let config_db_opts = config_db.identity.get_db_options();
        assert_eq!(config_db_opts.get_set_wal_dir(), "./identity-db-wall");
        assert!(config_db_opts.get_create_if_missing());
        assert!(config_db_opts.get_create_missing_columns());
        assert!(config_db_opts.get_set_error_if_exists());
    }
}

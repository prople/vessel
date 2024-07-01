use rst_common::standard::serde::{self, Deserialize};

#[derive(Deserialize, Debug)]
#[serde(crate = "self::serde")]
pub struct App {
    pub(super) host: String,
    pub(super) port: String,
}

impl App {
    pub fn get_app_config(&self) -> (String, String) {
        (self.host.to_owned(), self.port.to_owned())
    }
}

impl Default for App {
    fn default() -> Self {
        Self {
            host: "0.0.0.0".to_string(),
            port: "8080".to_string(),
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
    fn test_parse_app_config() -> Result<(), ConfigError> {
        let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        path.push("src/config/fixtures");

        let toml_file = format!("{}/config_app.toml", path.display());
        let config_toml = {
            let config_builder: Result<App, ConfigError> =
                Builder::new(from_file(toml_file)).fetch()?.parse(use_toml);

            config_builder
        };

        assert!(!config_toml.is_err());

        let config_app = config_toml.unwrap();
        assert_eq!(config_app.host, "localhost".to_string());
        assert_eq!(config_app.port, "8181".to_string());
        Ok(())
    }
}

use rst_common::standard::serde::{self, Deserialize};

use super::{Database, App};

#[derive(Deserialize, Debug)]
#[serde(crate = "self::serde")]
pub struct Config {
    pub(super) database: Database,
    pub(super) app: App,
}

impl Config {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn app(&self) -> &App {
        &self.app
    }

    pub fn db(&self) -> &Database {
        &self.database
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            database: Database::default(),
            app: App::default(),
        }
    }
}
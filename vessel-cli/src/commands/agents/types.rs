use cli_table::Table;

use rst_common::standard::serde::{self, Deserialize, Serialize};

pub(crate) const AGENT_FILE: &str = "agent.toml";
pub(crate) const AGENT_SESSION: &str = "agent.session";

#[derive(Serialize, Deserialize, Table, Clone)]
#[serde(crate = "self::serde")]
pub(crate) struct AgentConfig {
    #[table(title = "Name")]
    name: String,
    #[table(title = "Address")]
    addr: String,
}

impl AgentConfig {
    pub(crate) fn name(&self) -> String {
        self.name.to_owned()
    }
}

#[derive(Serialize, Deserialize)]
#[serde(crate = "self::serde")]
pub(crate) struct AgentToml {
    agents: Vec<AgentConfig>,
}

impl AgentToml {
    pub(crate) fn new(name: String, addr: String) -> Self {
        let agent_config = AgentConfig { name, addr };
        let mut agents: Vec<AgentConfig> = Vec::new();
        agents.push(agent_config);

        Self { agents }
    }

    pub(crate) fn add(&mut self, name: String, addr: String) {
        self.agents.push(AgentConfig { name, addr });
    }

    pub(crate) fn agents(&self) -> Vec<AgentConfig> {
        self.agents.clone()
    }
}
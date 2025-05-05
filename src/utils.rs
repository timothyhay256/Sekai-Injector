use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub app_version: String,
    pub apphash: String,
    pub inject_resources: bool,
    pub resource_config: String,
}

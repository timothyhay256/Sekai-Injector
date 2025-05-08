use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub inject_resources: bool,
    pub resource_config: String,
    pub upstream_host: String,
    pub target_ip: String,
    pub server_cert: String,
    pub server_key: String,
}

#[derive(Clone)]
pub struct Ports {
    pub http: u16,
    pub https: u16,
}

use std::collections::HashMap;

use axum::body::Body;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use serde::Deserialize;

pub type InjectionHashMap = HashMap<String, (String, bool)>;
type InjectionMapItem = Vec<(String, String, bool)>;

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

#[derive(Clone)]
pub struct Manager {
    pub injection_hashmap: InjectionHashMap,
    pub config: Config,
    pub client: Client<HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Body>,
    pub statistics: (i32, i32), // (proxied requests, injected requests)
}

#[derive(Clone, Deserialize)]
pub struct InjectionMap {
    pub map: InjectionMapItem,
}

pub struct CertificateGenParams<'a> {
    pub ca_cert_pem_path: &'a str,
    pub ca_key_pem_path: &'a str,
    pub target_hostname: &'a str,
    pub target_ip: &'a str,
    pub distinguished_common_name: &'a str,
    pub cert_file_out_path: &'a str,
    pub cert_key_out_path: &'a str,
    pub cert_lifetime_days: i64,
}

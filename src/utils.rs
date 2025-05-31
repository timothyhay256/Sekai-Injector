use std::collections::HashMap;

use axum::body::Body;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use local_ip_address::local_ip;
use serde::{Deserialize, Serialize};

pub type InjectionHashMap = HashMap<String, (String, bool)>;
type InjectionMapItem = Vec<(String, String, bool)>;
pub type RequestParams = (RequestStatus, String, Option<String>);

#[derive(Debug, Clone, Copy, Serialize)]
pub enum RequestStatus {
    Proxied,
    Forwarded,
}

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub inject_resources: bool,
    pub resource_config: String,
    pub upstream_host: String,
    pub target_ip: String,
    pub server_cert: String,
    pub server_key: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            inject_resources: true,
            resource_config: "injections.toml".to_string(),
            upstream_host: "assetbundle.sekai-en.com".to_string(),
            target_ip: local_ip().unwrap().to_string(),
            server_cert: "server_cert.pem".to_string(),
            server_key: "server_key.pem".to_string(),
        }
    }
}

#[derive(Clone)]
pub struct Ports {
    pub http: u16,
    pub https: u16,
}

impl Default for Ports {
    fn default() -> Self {
        Ports {
            http: 80,
            https: 443,
        }
    }
}

#[derive(Clone)]
pub struct Manager {
    pub injection_hashmap: InjectionHashMap,
    pub config: Config,
    pub client: Client<HttpsConnector<hyper_util::client::legacy::connect::HttpConnector>, Body>,
    pub statistics: ServerStatistics,
}

#[derive(Clone, Serialize)]
pub struct ServerStatistics {
    pub request_count: (i32, i32), // (proxied requests, injected requests)
    pub requests: Vec<RequestParams>, // (Type of request (proxied or injected), request path, Option<injected path>)
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

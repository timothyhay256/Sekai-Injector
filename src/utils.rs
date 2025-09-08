use std::{collections::HashMap, sync::Arc};

use axum::body::Body;
use hyper_rustls::HttpsConnector;
use hyper_util::client::legacy::Client;
use local_ip_address::local_ip;
use rustls::{
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};
use serde::{Deserialize, Serialize};

/// path to override, file to serve, enabled
pub type InjectionMapEntry = HashMap<String, (String, bool)>;
pub type InjectionHashMap = HashMap<String, InjectionMapEntry>;
type InjectionMapItem = Vec<(String, String, bool)>;
pub type RequestParams = (RequestStatus, String, Option<String>);

#[derive(Debug, Clone, Copy, Serialize)]
pub enum RequestStatus {
    Proxied,
    Forwarded,
}
#[derive(Deserialize, Debug, Clone)]
pub struct Domain {
    pub address: String,
    pub resource_config: String,
    pub server_cert: String,
    pub server_key: String,
    pub resource_prefix: Option<String>,
}

impl Default for Domain {
    fn default() -> Self {
        Domain {
            address: "assetbundle.sekai-en.com".to_string(),
            resource_config: "injections.toml".to_string(),
            server_cert: "server_cert.pem".to_string(),
            server_key: "server_key.pem".to_string(),
            resource_prefix: None,
        }
    }
}

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    pub inject_resources: bool,
    pub domains: Vec<Domain>,
    pub target_ip: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            inject_resources: true,
            domains: vec![Domain::default()],
            target_ip: local_ip().unwrap().to_string(),
        }
    }
}

impl Config {
    /// Returns three Vecs, contianing the domain address, cert path, and key path respectively.
    pub fn extract_domain_info(&self) -> (Vec<String>, Vec<String>, Vec<String>) {
        let addresses = self.domains.iter().map(|d| d.address.clone()).collect();
        let certs = self.domains.iter().map(|d| d.server_cert.clone()).collect();
        let keys = self.domains.iter().map(|d| d.server_key.clone()).collect();

        (addresses, certs, keys)
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
    /// (proxied requests, injected requests)
    pub request_count: (i32, i32),
    /// (Type of request (proxied or injected), request path, Option<injected path>)
    pub requests: Vec<RequestParams>,
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

#[derive(Debug)]
pub struct CustomCertResolver {
    pub map: HashMap<String, Arc<CertifiedKey>>,
}

impl CustomCertResolver {
    pub fn new() -> Self {
        CustomCertResolver {
            map: HashMap::new(),
        }
    }
}

impl Default for CustomCertResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl ResolvesServerCert for CustomCertResolver {
    fn resolve(&self, client_hello: ClientHello) -> Option<Arc<CertifiedKey>> {
        match client_hello.server_name() {
            Some(sni) => self.map.get(sni).cloned(),
            None => None, // No SNI information
        }
    }
}

use std::{
    collections::HashMap,
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::exit,
};

use axum::{body::Body, handler::Handler};
use axum_server::tls_rustls::RustlsConfig;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use log::error;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{Config, InjectionMap, Manager, Ports, routes};

pub async fn serve(config_holder: Config) {
    // Load injection map
    let injection_map = &config_holder.resource_config;

    if !Path::new(&injection_map).exists() {
        error!("Cannot read {}!", injection_map);
        exit(0);
    }

    let mut injection_map_file_contents = String::new();
    let mut injection_map_file = File::open(injection_map)
        .unwrap_or_else(|_| panic!("Could not open {injection_map}. Do I have permission?"));
    injection_map_file
        .read_to_string(&mut injection_map_file_contents)
        .expect(
            "The injection map file contains non UTF-8 characters, what in the world did you put in it??",
        );
    let injection_map: InjectionMap = toml::from_str(&injection_map_file_contents)
        .expect("The injection map file was not formatted properly and could not be read.");

    let injection_hashmap: HashMap<String, (String, bool)> = injection_map
        .map
        .into_iter()
        .map(|(path_to_override, file_to_serve, enabled)| {
            (path_to_override, (file_to_serve, enabled))
        })
        .collect();

    // Create a client to handle making HTTPS requests
    let https = HttpsConnectorBuilder::new()
        .with_webpki_roots()
        .https_or_http()
        .enable_all_versions()
        .build();

    let client = Client::builder(TokioExecutor::new()).build::<_, Body>(https);

    // Create manager containing our config and injection_hashmap and HTTPS client
    let manager = Manager {
        injection_hashmap,
        config: config_holder,
        client,
    };

    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=warn", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .try_init();

    let ports = Ports {
        http: 80,
        https: 443,
    };

    // optional: spawn a second server to redirect http requests to this server
    tokio::spawn(routes::redirect_http_to_https(ports.clone()));

    // configure certificate and private key used by https
    let config = RustlsConfig::from_pem_file(
        PathBuf::from(&manager.config.server_cert),
        PathBuf::from(&manager.config.server_key),
    )
    .await
    .unwrap();

    let app = routes::handler.with_state(manager);

    // run https server
    let addr = SocketAddr::from(([0, 0, 0, 0], ports.https));
    tracing::debug!("listening on {}", addr);
    axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

use std::{
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::exit,
    sync::Arc,
};

use axum::handler::Handler;
use axum_server::tls_rustls::RustlsConfig;
use log::{error, warn};
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{InjectionHashMap, InjectionMap, Manager, Ports, routes};

pub async fn serve(manager: Arc<RwLock<Manager>>) -> Arc<RwLock<Manager>> {
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=warn", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .try_init();

    let ports = Ports::default();

    // optional: spawn a second server to redirect http requests to this server
    tokio::spawn(routes::redirect_http_to_https(ports.clone()));

    // configure certificate and private key used by https
    let config = RustlsConfig::from_pem_file(
        PathBuf::from(&manager.read().await.config.server_cert),
        PathBuf::from(&manager.read().await.config.server_key),
    )
    .await
    .unwrap();

    let owned_manager = Arc::clone(&manager);
    let app = routes::handler.with_state(owned_manager);

    // run https server
    let addr = SocketAddr::from(([0, 0, 0, 0], ports.https));
    tracing::debug!("listening on {}", addr);
    match axum_server::bind_rustls(addr, config)
        .serve(app.into_make_service())
        .await
    {
        Ok(_) => {}
        Err(e) => panic!(
            "Failed to bind to 0.0.0.0:{}! You probably need to either run with root/admin, or run sudo setcap 'cap_net_bind_service=+ep' /path/to/binary to allow serving on port {}. Error: {}",
            ports.https, ports.https, e
        ),
    };

    manager
}

pub fn load_injection_map(injection_map_path: &String) -> InjectionHashMap {
    if !Path::new(&injection_map_path).exists() {
        warn!("Cannot read {injection_map_path}! Using default empty map.");
    }

    let mut injection_map_file_contents = String::new();

    let injection_map: InjectionMap = match File::open(injection_map_path) {
        Ok(mut file) => {
            file.read_to_string(&mut injection_map_file_contents).expect("The config file contains non UTF-8 characters, what in the world did you put in it??");
            toml::from_str(&injection_map_file_contents)
                .expect("The config file was not formatted properly and could not be read.")
        }
        Err(_) => {
            warn!("No valid injection map found, using empty map!");
            InjectionMap { map: Vec::new() }
        }
    };

    injection_map
        .map
        .into_iter()
        .map(|(path_to_override, file_to_serve, enabled)| {
            (path_to_override, (file_to_serve, enabled))
        })
        .collect()
}

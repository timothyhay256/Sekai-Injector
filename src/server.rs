use std::{collections::HashMap, fs::File, io::Read, net::SocketAddr, path::Path, sync::Arc};

use axum::handler::Handler;
use axum_server::tls_rustls::RustlsConfig;
use log::warn;
use rustls::ServerConfig;
use tokio::sync::RwLock;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use crate::{Config, InjectionHashMap, InjectionMap, Manager, Ports, load_certs, routes};

pub async fn serve(manager: Arc<RwLock<Manager>>) -> Arc<RwLock<Manager>> {
    let _ = tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| format!("{}=warn", env!("CARGO_CRATE_NAME")).into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .try_init();

    let ports = Ports::default();

    tokio::spawn(routes::redirect_http_to_https(ports.clone()));

    // load certs into an map to be used by custom resolver
    let cert_map =
        load_certs(&manager.read().await.config.domains).expect("Could not load certificates!");

    let tls_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(cert_map));

    let config = RustlsConfig::from_config(Arc::new(tls_config));

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

/// Load the injection hashmaps from the config, respecting any prefix set by
/// returning the path appended with the prefix in the returned `InjectionHashMap`
pub fn load_injection_maps(config: &Config) -> InjectionHashMap {
    let mut configs = HashMap::new();

    for domain in &config.domains {
        let injection_map_path = &domain.resource_config;

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

        configs.insert(
            domain.address.clone(),
            injection_map
                .map
                .into_iter()
                .map(|(path_to_override, file_to_serve, enabled)| {
                    (
                        {
                            if let Some(prefix) = &domain.resource_prefix {
                                let mut prefixed = String::new();

                                if !prefix.starts_with('/') {
                                    prefixed.push('/');
                                }

                                prefixed.push_str(prefix);

                                if !prefix.ends_with('/')
                                    && !path_to_override.starts_with("/")
                                    && !path_to_override.is_empty()
                                // In case the prefix is being used as the resource path
                                {
                                    prefixed.push('/');
                                }
                                format!("{prefixed}{path_to_override}")
                            } else {
                                path_to_override
                            }
                        },
                        (file_to_serve, enabled),
                    )
                })
                .collect(),
        );
    }
    configs
}

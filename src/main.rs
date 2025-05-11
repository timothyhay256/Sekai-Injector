mod certificates;
mod routes;
mod utils;

use std::{
    collections::HashMap,
    fs::File,
    io::{Read, Write},
    net::SocketAddr,
    path::{Path, PathBuf},
    process::exit,
};

use axum::{body::Body, handler::Handler};
use axum_server::tls_rustls::RustlsConfig;
use certificates::generate_certs_interactive;
use colored::Colorize;
use gumdrop::Options;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use log::{LevelFilter, debug, error, info};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};
use utils::{Config, InjectionMap, Manager, Ports};

#[derive(Debug, Options)]
struct CommandOptions {
    #[options(help = "print help message")]
    help: bool,
    #[options(help = "be verbose")]
    verbose: bool,
    #[options(help = "specify a specific config file")]
    config: Option<String>,

    #[options(command)]
    command: Option<Command>,
}

#[derive(Debug, Options)]
enum Command {
    #[options(help = "start the server")]
    Start(StartOptions),

    #[options(help = "interactively generate CA and certificates")]
    GenerateCerts(GenerateCertsOptions),

    #[options(help = "decrypt assetbundle")]
    Decrypt(DecryptOptions),

    #[options(help = "encrypt assetbundle")]
    Encrypt(EncryptOptions),
}

#[derive(Debug, Options)]
struct StartOptions {}

#[derive(Debug, Options)]
struct GenerateCertsOptions {}

#[derive(Debug, Options)]
struct DecryptOptions {
    #[options(help = "file to decrypt", required)]
    encrypted_path: PathBuf,

    #[options(help = "output file", required)]
    output: PathBuf,
}

#[derive(Debug, Options)]
struct EncryptOptions {
    #[options(help = "file to encrypt", required)]
    decrypted_path: PathBuf,

    #[options(help = "output file", required)]
    output: PathBuf,
}

#[tokio::main]
async fn main() {
    let opts = CommandOptions::parse_args_default_or_exit();

    let mut builder = env_logger::Builder::new();

    if opts.verbose {
        builder.filter_level(LevelFilter::Debug);
    } else {
        builder.filter_level(LevelFilter::Info);
    }
    builder.init();

    let config_path = match opts.config {
        Some(config) => config,
        None => "sekai-injector.toml".to_string(),
    };

    info!("{}", "ハローセカイ!".green());

    debug!("Using config: {config_path}");

    let config_path = Path::new(&config_path);

    let mut config_file_contents = String::new();
    let mut config_file =
        File::open(config_path).expect("Could not open config file. Do I have permission?");
    config_file
        .read_to_string(&mut config_file_contents)
        .expect(
            "The config file contains non UTF-8 characters, what in the world did you put in it??",
        );
    let config_holder: Config = toml::from_str(&config_file_contents)
        .expect("The config file was not formatted properly and could not be read.");

    if let Some(Command::GenerateCerts(ref _generate_certs_options)) = opts.command {
        generate_certs_interactive(&config_holder);
    } else if let Some(Command::Decrypt(ref decrypt_options)) = opts.command {
        info!(
            "Decrypting assetbundle {} into {}",
            decrypt_options.encrypted_path.display(),
            decrypt_options.output.display()
        );
        info!(
            "All credit for reverse engineering assetbundle encryption goes to https://github.com/mos9527"
        );

        match decrypt(&decrypt_options.encrypted_path, &decrypt_options.output) {
            Ok(_) => {
                info!("Output saved to {}", decrypt_options.output.display())
            }
            Err(e) => {
                error!(
                    "Could not decrypt {}: {}",
                    decrypt_options.encrypted_path.display(),
                    e
                )
            }
        };
    } else if let Some(Command::Encrypt(ref encrypt_options)) = opts.command {
        info!(
            "Encrypting assetbundle {} into {}",
            encrypt_options.decrypted_path.display(),
            encrypt_options.output.display()
        );
        info!(
            "All credit for reverse engineering assetbundle encryption goes to https://github.com/mos9527"
        );

        match encrypt(&encrypt_options.decrypted_path, &encrypt_options.output) {
            Ok(_) => {
                info!("Output saved to {}", encrypt_options.output.display())
            }
            Err(e) => {
                error!(
                    "Could not decrypt {}: {}",
                    encrypt_options.decrypted_path.display(),
                    e
                )
            }
        };
    } else if let Some(Command::Start(ref _start_options)) = opts.command {
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
}

// This is all Project Sekai specific. As such, it may be removed without warning.
fn decrypt(infile: &Path, outfile: &Path) -> std::io::Result<()> {
    // All credit for figuring out decryption goes to https://github.com/mos9527

    let mut fin = File::open(infile)?;
    let mut magic = [0u8; 4];
    fin.read_exact(&mut magic)?;

    let mut fout = File::create(outfile)?;

    if magic == [0x10, 0x00, 0x00, 0x00] {
        for _ in (0..128).step_by(8) {
            let mut block = [0u8; 8];
            fin.read_exact(&mut block)?;
            for i in 0..5 {
                block[i] = !block[i];
            }
            fout.write_all(&block)?;
        }
        let mut buffer = [0u8; 8];
        while fin.read_exact(&mut buffer).is_ok() {
            fout.write_all(&buffer)?;
        }
    } else {
        println!("copy {:?} -> {:?}", infile, outfile);
        let mut buffer = [0u8; 8];
        fout.write_all(&magic)?; // Write already-read magic
        while fin.read_exact(&mut buffer).is_ok() {
            fout.write_all(&buffer)?;
        }
    }

    Ok(())
}

fn encrypt(infile: &Path, outfile: &Path) -> std::io::Result<()> {
    let mut fin = File::open(infile)?;
    let mut fout = File::create(outfile)?;

    // Write the magic number
    fout.write_all(&[0x10, 0x00, 0x00, 0x00])?;

    // Encrypt the first 128 bytes (16 blocks of 8 bytes)
    for _ in (0..128).step_by(8) {
        let mut block = [0u8; 8];
        if fin.read_exact(&mut block).is_ok() {
            for i in 0..5 {
                block[i] = !block[i];
            }
            fout.write_all(&block)?;
        } else {
            break; // File is smaller than 128 bytes
        }
    }

    // Copy the rest of the file as-is
    let mut buffer = [0u8; 8];
    while fin.read_exact(&mut buffer).is_ok() {
        fout.write_all(&buffer)?;
    }

    Ok(())
}

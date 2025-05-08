mod certificates;
mod routes;
mod utils;

use axum::{Router, routing::get};
use axum_server::tls_rustls::RustlsConfig;
use certificates::generate_certs_interactive;
use colored::Colorize;
use env_logger::Builder;
use gumdrop::Options;
use log::LevelFilter;
use log::{debug, error, info};
use std::fs::File;
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

use utils::Config;
use utils::Ports;

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

    let mut builder = Builder::new();

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
        tracing_subscriber::registry()
            .with(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| format!("{}=debug", env!("CARGO_CRATE_NAME")).into()),
            )
            .with(tracing_subscriber::fmt::layer())
            .init();

        let ports = Ports {
            http: 7878,
            https: 3000,
        };
        // optional: spawn a second server to redirect http requests to this server
        tokio::spawn(routes::redirect_http_to_https(ports.clone()));

        // configure certificate and private key used by https
        let config = RustlsConfig::from_pem_file(
            PathBuf::from(&config_holder.server_cert),
            PathBuf::from(&config_holder.server_key),
        )
        .await
        .unwrap();

        let cloned_config = config_holder.clone();
        let app = Router::new()
            .route("/", get(routes::handler))
            .with_state(cloned_config);

        // run https server
        let addr = SocketAddr::from(([127, 0, 0, 1], ports.https));
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

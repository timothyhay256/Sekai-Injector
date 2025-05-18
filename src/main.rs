use std::{
    fs::File,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::body::Body;
use gumdrop::Options;
use hyper_rustls::HttpsConnectorBuilder;
use hyper_util::{client::legacy::Client, rt::TokioExecutor};
use log::{LevelFilter, debug, error, info};
use sekai_injector::{
    Config, Manager, certificates::generate_certs_interactive, load_injection_map, server,
};
use tokio::sync::RwLock;

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
        let injection_hashmap = load_injection_map(&config_holder.resource_config);

        // Create a client to handle making HTTPS requests
        let https = HttpsConnectorBuilder::new()
            .with_webpki_roots()
            .https_or_http()
            .enable_all_versions()
            .build();

        let client = Client::builder(TokioExecutor::new()).build::<_, Body>(https);

        // Create manager containing our config and injection_hashmap and HTTPS client
        let manager = Arc::new(RwLock::new(Manager {
            injection_hashmap,
            config: config_holder,
            client,
            statistics: (0, 0),
        }));

        server::serve(manager).await;
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
            (0..5).for_each(|i| {
                block[i] = !block[i];
            });
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
            (0..5).for_each(|i| {
                block[i] = !block[i];
            });
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

use std::{fs::File, io::Write, path::Path, process::exit};

use colored::Colorize;
use inquire::{CustomType, Text};
use log::{error, info};
use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SerialNumber,
};
use time::{Duration, OffsetDateTime};

use crate::utils::Config;

pub fn generate_ca(
    ca_common_name: String,
    ca_lifetime_days: i64,
    cert_file_path: String,
    cert_key_path: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Set up parameters for the CA
    let mut params = CertificateParams::default();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(ca_lifetime_days);

    // Set the Distinguished Name and other fields to make the CA seem real
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, ca_common_name);
    dn.push(DnType::OrganizationName, "Sekai Injector Organization");
    dn.push(DnType::CountryName, "JP");
    params.distinguished_name = dn;
    params.use_authority_key_identifier_extension = true;
    params.serial_number = Some(SerialNumber::from(rand::random::<u64>()));

    // Generate a key pair and create the self-signed CA certificate
    let key_pair = KeyPair::generate()?;
    let ca_cert = params.self_signed(&key_pair)?;

    // Save the CA certificate and private key to files
    let mut cert_file = File::create(cert_file_path)?;
    cert_file.write_all(ca_cert.pem().as_bytes())?;

    let mut key_file = File::create(cert_key_path)?;
    key_file.write_all(key_pair.serialize_pem().as_bytes())?;

    Ok(())
}

pub fn new_self_signed_cert(
    ca_cert_pem_path: String,
    ca_key_pem_path: String,
    target_hostname: String,
    target_ip: String,
    distinguished_common_name: String,
    cert_file_out_path: String,
    cert_key_out_path: String,
    cert_lifetime_days: i64,
) -> Result<(), Box<dyn std::error::Error>> {
    // Load the CA certificate and key
    let ca_cert_pem = std::fs::read_to_string(ca_cert_pem_path)?;
    let ca_key_pem = std::fs::read_to_string(ca_key_pem_path)?;
    let ca_cert_params = CertificateParams::from_ca_cert_pem(&ca_cert_pem)?;
    let ca_key = KeyPair::from_pem(&ca_key_pem)?;
    let ca_cert = ca_cert_params.self_signed(&ca_key)?;

    // Set up parameters for the server certificate
    let mut params = CertificateParams::new(vec![target_hostname, target_ip.to_string()])?;
    params.key_usages = vec![
        KeyUsagePurpose::DigitalSignature,
        KeyUsagePurpose::KeyEncipherment,
    ];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.not_before = OffsetDateTime::now_utc();
    params.not_after = OffsetDateTime::now_utc() + Duration::days(cert_lifetime_days);

    // Set the Distinguished Name
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, distinguished_common_name);
    params.distinguished_name = dn;

    // Generate a key pair and create the server certificate signed by the CA
    let key_pair = KeyPair::generate()?;
    let server_cert = params.signed_by(&key_pair, &ca_cert, &ca_key)?;

    // Save the server certificate and private key to files
    let mut cert_file = File::create(cert_file_out_path)?;
    cert_file.write_all(server_cert.pem().as_bytes())?;

    let mut key_file = File::create(cert_key_out_path)?;
    key_file.write_all(key_pair.serialize_pem().as_bytes())?;

    Ok(())
}

pub fn generate_certs_interactive(config_holder: &Config) {
    info!("{}\n{}", "\n!!! WARNING WARNING WARNING !!!".red(), "Never ever share any certificate or CA files with other people!\nIf you do, they could use it to compromise any devices you installed the certificate on!".yellow());
    info!("If you don't know what to put, just press enter for the defaults.");
    info!("Generating CA");
    let ca_common_name = Text::new("What should the CA be named?")
        .with_default("Sekai Injector CA")
        .prompt()
        .unwrap();

    let ca_lifetime_days: i64 = CustomType::new("How many days should the CA be valid?")
        .with_error_message("Please type a valid number")
        .with_default(3650)
        .prompt()
        .unwrap();

    let ca_cert_file_path = Text::new("Certificate path output")
        .with_default("ca_cert.pem")
        .prompt()
        .unwrap();

    let ca_cert_key_path = Text::new("Certificate path output")
        .with_default("ca_key.pem")
        .prompt()
        .unwrap();

    if !Path::new(&ca_cert_file_path).exists() && !Path::new(&ca_cert_key_path).exists() {
        match generate_ca(
            ca_common_name,
            ca_lifetime_days,
            ca_cert_file_path.clone(),
            ca_cert_key_path.clone(),
        ) {
            Ok(_) => info!("Succesfully generated CA!"),
            Err(e) => {
                error!("There was an issue generating the CA: {e}");
                exit(1);
            }
        }
    } else {
        error!("Will not overwrite existing certificate!");
        exit(1);
    }

    info!("Signing new certificate with CA");

    let target_hostname = Text::new("What should the target hostname be?")
        .with_default(&config_holder.upstream_host)
        .prompt()
        .unwrap();

    let target_ip = Text::new("What should the target IP be?")
        .with_default(&config_holder.target_ip)
        .prompt()
        .unwrap();

    let cert_lifetime_days: i64 = CustomType::new("How many days should the certificate be valid?")
        .with_error_message("Please type a valid number")
        .with_default(3650)
        .prompt()
        .unwrap();

    let ca_cert_pem_path = Text::new("CA certificate path")
        .with_default("ca_cert.pem")
        .prompt()
        .unwrap();

    let ca_key_pem_path = Text::new("CA certificate path")
        .with_default("ca_key.pem")
        .prompt()
        .unwrap();

    let distinguished_common_name = config_holder.upstream_host.clone();

    let cert_file_out_path = Text::new("Signed certificate output")
        .with_default(&config_holder.server_cert)
        .prompt()
        .unwrap();

    let cert_key_out_path = Text::new("Signed certificate key output")
        .with_default(&config_holder.server_key)
        .prompt()
        .unwrap();

    match new_self_signed_cert(
        ca_cert_pem_path,
        ca_key_pem_path,
        target_hostname,
        target_ip,
        distinguished_common_name,
        cert_file_out_path.clone(),
        cert_key_out_path.clone(),
        cert_lifetime_days,
    ) {
        Ok(_) => info!("Succesfully signed certificate with CA"),
        Err(e) => {
            error!("There was an issue signing the certificate: {e}");
            exit(1);
        }
    }
    info!(
        "\nFinished generating CA and certificates. Remember to NEVER share the following files with anyone else: \n{}\n{}\n{}\n{}",
        &ca_cert_file_path, &ca_cert_key_path, &cert_file_out_path, &cert_key_out_path
    );
}

#![allow(clippy::complexity, clippy::style, clippy::pedantic)]

fn main() -> Result<(), Box<dyn std::error::Error>> {
    example()
}

#[cfg(not(target_family = "wasm"))]
fn example() -> Result<(), Box<dyn std::error::Error>> {
    use rand::rngs::OsRng;
    use rsa::pkcs8::ToPrivateKey;
    use rsa::RsaPrivateKey;

    use rcgen::{date_time_ymd, Certificate, CertificateParams, DistinguishedName};
    use std::convert::TryFrom;
    use std::fs;

    let mut params: CertificateParams = Default::default();
    params.not_before = date_time_ymd(2021, 05, 19);
    params.not_after = date_time_ymd(4096, 01, 01);
    params.distinguished_name = DistinguishedName::new();

    params.alg = &rcgen::PKCS_RSA_SHA256;

    let mut rng = OsRng;
    let bits = 2048;
    let private_key = RsaPrivateKey::new(&mut rng, bits)?;
    let private_key_der = private_key.to_pkcs8_der()?;
    let key_pair = rcgen::KeyPair::try_from(private_key_der.as_ref()).unwrap();
    params.key_pair = Some(key_pair);

    let cert = Certificate::from_params(params)?;
    let pem_serialized = cert.serialize_pem()?;
    let der_serialized = pem::parse(&pem_serialized).unwrap().contents;
    let hash = ring::digest::digest(&ring::digest::SHA512, &der_serialized);
    let hash_hex: String = hash.as_ref().iter().map(|b| format!("{:02x}", b)).collect();
    println!("sha-512 fingerprint: {}", hash_hex);
    println!("{}", pem_serialized);
    println!("{}", cert.serialize_private_key_pem());
    std::fs::create_dir_all("certs/")?;
    fs::write("certs/cert.pem", &pem_serialized.as_bytes())?;
    fs::write("certs/cert.der", &der_serialized)?;
    fs::write(
        "certs/key.pem",
        &cert.serialize_private_key_pem().as_bytes(),
    )?;
    fs::write("certs/key.der", &cert.serialize_private_key_der())?;
    Ok(())
}

#[cfg(target_family = "wasm")]
fn example() -> Result<(), Box<dyn std::error::Error>> {
    panic!("WASM is not supported");
}

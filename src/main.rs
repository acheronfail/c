use std::error::Error;
use std::fs::OpenOptions;
use std::io::{stdin, Read, Write};
use std::path::PathBuf;

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use argon2::password_hash::SaltString;
use argon2::{Argon2, ParamsBuilder, PasswordHasher};
use base64_simd::STANDARD_NO_PAD as b64;
use clap::{Parser, ValueEnum};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum Action {
    Encrypt,
    Decrypt,
}

/// The password is read from STDIN
#[derive(Debug, Parser)]
struct Cli {
    action: Action,
    in_file: PathBuf,
    out_file: PathBuf,
}

fn main() -> Result<(), Box<dyn Error>> {
    let args = Cli::parse();

    let plaintext = {
        let mut buf = vec![];
        OpenOptions::new()
            .read(true)
            .open(&args.in_file)
            .unwrap()
            .read_to_end(&mut buf)
            .unwrap();

        buf
    };

    let (password, password_salt, nonce) = {
        let mut stdin = stdin().lock();
        let mut pw = String::new();
        stdin.read_to_string(&mut pw).expect("failed reading STDIN");

        let pw = pw.trim().to_string();
        let salt = b64.encode_to_string(&pw.as_bytes());
        let nonce = b64.encode_to_string(&salt.as_bytes());
        let nonce = nonce.chars().take(12).collect::<String>();
        (pw, salt, nonce)
    };

    assert!(password.len() > 20);
    assert!(password_salt.len() > 8);
    assert_eq!(nonce.len(), 12);

    // hash
    let hash = {
        eprintln!("Hashing...");

        let salt = b64.encode_to_string(password_salt);
        let salt = SaltString::from_b64(&salt).expect("salt wasn't valid");
        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            ParamsBuilder::new()
                .m_cost(4_096 * 1024)
                .t_cost(10)
                .p_cost(10)
                .output_len(32)
                .build()
                .expect("failed to create argon2 params"),
        );

        let pw_hash = argon2
            .hash_password(password.as_bytes(), &salt)
            .expect("failed to create argon2 hash");

        pw_hash.hash.unwrap().to_string()
    };

    // crypto
    {
        match args.action {
            Action::Encrypt => eprintln!("encrypting..."),
            Action::Decrypt => eprintln!("decrypting..."),
        }

        let key = b64.decode_to_vec(&hash)?;
        let key = Key::<Aes256Gcm>::from_slice(&key);
        let cipher = Aes256Gcm::new(&key);
        let nonce = Nonce::from_slice(nonce.as_bytes());

        let data = match args.action {
            Action::Encrypt => cipher.encrypt(&nonce, &plaintext[..]).unwrap(),
            Action::Decrypt => cipher.decrypt(&nonce, &plaintext[..]).unwrap(),
        };

        OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&args.out_file)
            .unwrap()
            .write_all(&data)
            .unwrap();
    }

    Ok(())
}

use openssl::derive::Deriver;
use openssl::ec::{EcGroup, EcKey};
use openssl::encrypt::{Decrypter, Encrypter};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::rsa::{Padding, Rsa};

// https://docs.rs/openssl/0.10.38/openssl/encrypt/index.html
// https://docs.rs/openssl/0.10.38/openssl/ec/struct.EcKey.html
// https://jameshfisher.com/2017/04/14/openssl-ecc/
fn main() {
    // Generate a RSA keypair
    let rsa_keypair = Rsa::generate(2048).unwrap();
    let rsa_keypair = PKey::from_rsa(rsa_keypair).unwrap();
    println!(
        "rsa_pub_key: \n{}",
        std::str::from_utf8(&rsa_keypair.public_key_to_pem().unwrap()).unwrap()
    );

    // Generate a ECC keypair
    let ec_g = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let ec_keypair1 = EcKey::generate(&ec_g).unwrap();
    let ec_keypair1 = PKey::from_ec_key(ec_keypair1).unwrap();
    let ec_keypair2 = EcKey::generate(&ec_g).unwrap();
    let ec_keypair2 = PKey::from_ec_key(ec_keypair2).unwrap();
    // Generate a ECDH shared secret
    let mut deriver1 = Deriver::new(&ec_keypair1).unwrap();
    deriver1.set_peer(&ec_keypair2).unwrap();
    let shared_key1 = deriver1.derive_to_vec().unwrap();
    println!("shared_key1: {:?}", shared_key1);
    let mut deriver2 = Deriver::new(&ec_keypair2).unwrap();
    deriver2.set_peer(&ec_keypair1).unwrap();
    let shared_key2 = deriver2.derive_to_vec().unwrap();
    println!("shared_key2: {:?}", shared_key2);
    assert_eq!(shared_key1, shared_key2);
    // TODO: use shared_key to encrypt and decrypt

    // TODO: read data from file
    let data = b"hello, world!";

    // Encrypt the data with RSA PKCS1
    let mut encrypter = Encrypter::new(&rsa_keypair).unwrap();
    encrypter.set_rsa_padding(Padding::PKCS1).unwrap();
    // let mut encrypter2 = Encrypter::new(&dh_key1).unwrap();
    // Create an output buffer
    let buffer_len = encrypter.encrypt_len(data).unwrap();
    let mut encrypted = vec![0; buffer_len];
    // Encrypt and truncate the buffer
    let encrypted_len = encrypter.encrypt(data, &mut encrypted).unwrap();
    encrypted.truncate(encrypted_len);

    // Decrypt the data
    let mut decrypter = Decrypter::new(&rsa_keypair).unwrap();
    decrypter.set_rsa_padding(Padding::PKCS1).unwrap();
    // Create an output buffer
    let buffer_len = decrypter.decrypt_len(&encrypted).unwrap();
    let mut decrypted = vec![0; buffer_len];
    // Encrypt and truncate the buffer
    let decrypted_len = decrypter.decrypt(&encrypted, &mut decrypted).unwrap();
    decrypted.truncate(decrypted_len);
    assert_eq!(&*decrypted, data);

    // print string
    let input_str = String::from_utf8(data.to_vec()).unwrap();
    let decrypted_str = String::from_utf8(decrypted).unwrap();
    println!("input            : {}", input_str);
    println!("rsa_encrypted_bin: {:?}", encrypted);
    println!("rsa_decrypted    : {}", decrypted_str);
}

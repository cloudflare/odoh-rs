# odoh-rs

[![Latest Version]][crates.io]
[![docs.rs](https://docs.rs/odoh-rs/badge.svg)](https://docs.rs/odoh-rs)

[Latest Version]: https://img.shields.io/crates/v/odoh-rs.svg
[crates.io]: https://crates.io/crates/odoh-rs

[odoh-rs] is a library that implements [Oblivious DNS over HTTPS (ODoH) protocol draft-03] in Rust.

It can be used to implement an ODoH client or server (target).
[odoh-client-rs] uses `odoh-rs` to implement its functionality, and is a good source of API usage examples, along with the tests in `odoh-rs`, in particular [test_vectors_for_odoh].

This library is interoperable with [odoh-go].

`odoh-rs` uses [hpke] as the underlying HPKE implementation. It supports the default Oblivious DoH ciphersuite
`(KEM: X25519HkdfSha256, KDF: HkdfSha256, AEAD: AesGcm128)`.

It does not provide full crypto agility.

[odoh-rs]: https://github.com/cloudflare/odoh-rs/
[Oblivious DNS over HTTPS (ODoH) protocol draft-03]: https://tools.ietf.org/html/draft-pauly-dprive-oblivious-doh-03
[odoh-client-rs]: https://github.com/cloudflare/odoh-client-rs/
[odoh-go]: https://github.com/cloudflare/odoh-go
[test_vectors_for_odoh]: https://github.com/cloudflare/odoh-rs/src/protocol.rs#L639
[hpke]: https://docs.rs/hpke/0.3.1/hpke/index.html
[protocol.rs]: https://github.com/cloudflare/odoh-rs/src/protocol.rs

# Example API Usage

This example outlines the steps necessary for a successful ODoH query.

```rust
// Server generates a secret key pair
fn generate_key_pair() -> ObliviousDoHKeyPair {
    // random bytes, should be 32 bytes for X25519 keys
    let ikm = rand::thread_rng().gen::<[u8; 32]>();;
    let (secret_key, public_key) = derive_keypair_from_seed(&ikm);
    let public_key_bytes = public_key.to_bytes().to_vec();
    let odoh_public_key = ObliviousDoHConfigContents {
        kem_id: 0x0020,  // DHKEM(X25519, HKDF-SHA256)
        kdf_id: 0x0001,  // KDF(SHA-256)
        aead_id: 0x0001, // AEAD(AES-GCM-128)
        public_key: public_key_bytes,
    };
    ObliviousDoHKeyPair {
        private_key: secret_key,
        public_key: odoh_public_key,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Server generates a key pair and creates an `ObliviousDoHConfigs` struct from it
    // which it will distribute to clients via HTTPS records as outlined in the draft:
    // https://tools.ietf.org/html/draft-pauly-dprive-oblivious-doh-02#section-5
    let key_pair = generate_key_pair();
    let config = ObliviousDoHConfig::new(&key_pair.public_key.clone().to_bytes().unwrap()).unwrap();
    let odohconfig = ObliviousDoHConfigs {
        configs: vec![config.clone()],
    }
    .to_bytes()
    .unwrap();

    // Client gets `odohconfig` via an HTTPS record
    let client_config = get_supported_config(&odohconfig).unwrap();

    // Client creates a query body
    let query = ObliviousDoHQueryBody::new(&vec![1, 2], Some(2));

    // Client creates a query to send to the server
    let (oblivious_query, client_secret) = create_query_msg(&client_config, &query).unwrap();

    // Server receives the query and parses it
    let (parsed_query, server_secret) = parse_received_query(&key_pair, &oblivious_query)
        .await
        .unwrap();

    // Server generates a DNS response based on the query
    let resolver_resp = vec![1, 3, 4];

    // Server creates an encrypted response msg to send to the client
    let generated_response = create_response_msg(&server_secret, &resolver_resp, None, &query)
        .await
        .unwrap();

    // Client receives the server's encrypted DNS response and parses it to recover the plaintext DNS response.
    let parsed_response =
        parse_received_response(&client_secret, &generated_response, &query).unwrap();
    Ok(())
}

```

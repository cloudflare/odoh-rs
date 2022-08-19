# odoh-rs

[![Latest Version]][crates.io]
[![docs.rs](https://docs.rs/odoh-rs/badge.svg)](https://docs.rs/odoh-rs)

[Latest Version]: https://img.shields.io/crates/v/odoh-rs.svg
[crates.io]: https://crates.io/crates/odoh-rs

[odoh-rs] is a library that implements [RFC 9230] Oblivious DNS over HTTPS protocol in Rust.

It can be used to implement an ODoH client or server (target).
[odoh-client-rs] uses `odoh-rs` to implement its functionality, and is a good source of API usage examples, along with the tests in `odoh-rs`, in particular [test_vectors_for_odoh].

This library is interoperable with [odoh-go].

`odoh-rs` uses [hpke] as the underlying HPKE implementation. It supports the default Oblivious DoH ciphersuite
`(KEM: X25519HkdfSha256, KDF: HkdfSha256, AEAD: AesGcm128)`.

It does not provide full crypto agility.

[odoh-rs]: https://github.com/cloudflare/odoh-rs/
[RFC 9230]: https://datatracker.ietf.org/doc/rfc9230/
[odoh-client-rs]: https://github.com/cloudflare/odoh-client-rs/
[odoh-go]: https://github.com/cloudflare/odoh-go
[test_vectors_for_odoh]: https://github.com/cloudflare/odoh-rs/blob/master/tests/test-vectors.json
[hpke]: https://github.com/rozbb/rust-hpke

# Example API Usage

This example outlines the steps necessary for a successful ODoH query.

```rust
// Use a seed to initialize a RNG. *Note* you should rely on some
// random source.
let mut rng = StdRng::from_seed([0; 32]);

// Generate a key pair on server side.
let key_pair = ObliviousDoHKeyPair::new(&mut rng);

// Create client configs from the key pair. It can be distributed
// to the clients.
let public_key = key_pair.public().clone();
let client_configs: ObliviousDoHConfigs = vec![ObliviousDoHConfig::from(public_key)].into();
let client_configs_bytes = compose(&client_configs).unwrap().freeze();

// ... distributing client_configs_bytes ...

// Parse and extract first supported config from client configs on client side.
let client_configs: ObliviousDoHConfigs = parse(&mut client_configs_bytes.clone()).unwrap();
let client_config = client_configs.into_iter().next().unwrap();
let config_contents = client_config.into();

// This is a example client request. This library doesn't validate
// DNS message.
let query = ObliviousDoHMessagePlaintext::new(b"What's the IP of one.one.one.one?", 0);

// Encrypt the above request. The client_secret returned will be
// used later to decrypt server's response.
let (query_enc, cli_secret) = encrypt_query(&query, &config_contents, &mut rng).unwrap();

// ... sending query_enc to the server ...

// Server decrypt request.
let (query_dec, srv_secret) = decrypt_query(&query_enc, &key_pair).unwrap();
assert_eq!(query, query_dec);

// Server could now resolve the decrypted query, and compose a response.
let response = ObliviousDoHMessagePlaintext::new(b"The IP is 1.1.1.1", 0);

// server encrypt response
let nonce = ResponseNonce::default();
let response_enc = encrypt_response(&query_dec, &response, srv_secret, nonce).unwrap();

// ... sending response_enc back to the client ...

// client descrypt response
let response_dec = decrypt_response(&query, &response_enc, cli_secret).unwrap();
assert_eq!(response, response_dec);
```

//! Utility APIs for handling ODoH keys

use hpke::{kem::X25519HkdfSha256, kex::KeyExchange, Kem as KemTrait};

pub type Kem = X25519HkdfSha256;
pub type Kex = <Kem as KemTrait>::Kex;

/// Takes secret keying material and produces the corresponding HPKE key pair.
/// `ikm` length should be the same as key length, which means 32 bytes for X25519 keys.
///
/// This is necessary because HPKE does not specify a serialization format for private keys.
pub fn derive_keypair_from_seed(
    ikm: &[u8],
) -> (
    <Kex as KeyExchange>::PrivateKey,
    <Kex as KeyExchange>::PublicKey,
) {
    Kem::derive_keypair(&ikm)
}

//! API for protocol functionality such as creating and parsing ODoH queries and responses.

#![deny(missing_docs)]

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{AeadInPlace, NewAead};
use aes_gcm::Aes128Gcm;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use hkdf::Hkdf;
use hpke::aead::{AeadTag, AesGcm128};
use hpke::kdf::{HkdfSha256, Kdf as KdfTrait};
use hpke::kem::X25519HkdfSha256;
use hpke::kex::KeyExchange;
use hpke::{
    Deserializable, EncappedKey, HpkeError, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use rand::{CryptoRng, RngCore};
use std::convert::{TryFrom, TryInto};
use thiserror::Error as ThisError;

// Extra info string used by various crypto routines.
const LABEL_QUERY: &[u8] = b"odoh query";
const LABEL_KEY: &[u8] = b"odoh key";
const LABEL_NONCE: &[u8] = b"odoh nonce";
const LABEL_KEY_ID: &[u8] = b"odoh key id";
const LABEL_RESPONSE: &[u8] = b"odoh response";

// Identifier this crate supports.
const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0001;

/// For the selected KDF: SHA256
const KDF_OUTPUT_SIZE: usize = 32;
const AEAD_KEY_SIZE: usize = 16;
const AEAD_NONCE_SIZE: usize = 12;
const AEAD_TAG_SIZE: usize = 16;

/// This is the maximum of `AEAD_KEY_SIZE` and `AEAD_NONCE_SIZE`
const RESPONSE_NONCE_SIZE: usize = 16;

/// Length of public key used in config
const PUBLIC_KEY_SIZE: usize = 32;

type Kem = X25519HkdfSha256;
type Aead = AesGcm128;
type Kdf = HkdfSha256;
type Kex = <Kem as KemTrait>::Kex;

type AeadKey = [u8; AEAD_KEY_SIZE];
type AeadNonce = [u8; AEAD_NONCE_SIZE];

/// Secret used in encrypt/decrypt API.
pub type OdohSecret = [u8; AEAD_KEY_SIZE];

/// Response nonce needed by [`encrypt_response`](fn.encrypt_response.html)
pub type ResponseNonce = [u8; RESPONSE_NONCE_SIZE];

/// HTTP content-type header required for sending queries and responses
pub const ODOH_HTTP_HEADER: &str = "application/oblivious-dns-message";

/// ODoH version supported by this library
pub const ODOH_VERSION: u16 = 0xff06;

/// Errors generated by this crate.
#[derive(ThisError, Debug, Clone)]
pub enum Error {
    /// Input data is too short.
    #[error("Input data is too short")]
    ShortInput,
    /// Input data has incorrect length.
    #[error("Input data has incorrect length")]
    InvalidInputLength,
    /// Padding is not zero.
    #[error("Padding is not zero")]
    InvalidPadding,
    /// Config parameter is invalid.
    #[error("Config parameter is invalid")]
    InvalidParameter,
    /// Type byte in ObliviousDoHMessage is invalid.
    #[error("Type byte in ObliviousDoHMessage is invalid")]
    InvalidMessageType,
    /// Message key_id does not match public key.
    #[error("Message key_id does not match public key")]
    KeyIdMismatch,
    /// Response nonce is not equal to max(key, nonce) size.
    #[error("Response nonce is not equal to max(key, nonce) size")]
    InvalidResponseNonceLength,

    // HpkeError doesn't support Eq
    /// Errors from hpke crate.
    #[error(transparent)]
    Hpke(#[from] HpkeError),

    /// Errors from aes-gcm crate.
    #[error(transparent)]
    AesGcm(#[from] aes_gcm::Error),

    /// Unexpected internal error.
    #[error("Unexpected internal error")]
    Internal,
}

type Result<T, E = Error> = std::result::Result<T, E>;

/// Serialize to IETF wireformat that is similar to [XDR](https://tools.ietf.org/html/rfc1014)
pub trait Serialize {
    /// Serialize the provided struct into the buf.
    fn serialize<B: BufMut>(self, buf: &mut B) -> Result<()>;
}

/// Deserialize from IETF wireformat that is similar to [XDR](https://tools.ietf.org/html/rfc1014)
pub trait Deserialize {
    /// Deserialize a struct from the buf.
    fn deserialize<B: Buf>(buf: &mut B) -> Result<Self>
    where
        Self: Sized;
}

/// Convenient function to deserialize a structure from Bytes.
pub fn parse<D: Deserialize, B: Buf>(buf: &mut B) -> Result<D> {
    D::deserialize(buf)
}

/// Convenient function to serialize a structure into a new BytesMut.
pub fn compose<S: Serialize>(s: S) -> Result<BytesMut> {
    let mut buf = BytesMut::new();
    s.serialize(&mut buf)?;
    Ok(buf)
}

fn read_lengthed<B: Buf>(b: &mut B) -> Result<Bytes> {
    if b.remaining() < 2 {
        return Err(Error::ShortInput);
    }

    let len = b.get_u16() as usize;

    if len > b.remaining() {
        return Err(Error::InvalidInputLength);
    }

    Ok(b.copy_to_bytes(len))
}

/// Supplies config information to the client.
///
/// It contains one or more `ObliviousDoHConfig` structures in
/// decreasing order of preference. This allows a server to support multiple versions
/// of ODoH and multiple sets of ODoH HPKE suite parameters.
///
/// This information is designed to be disseminated via [DNS HTTPS
/// records](https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-03),
/// using the param `odohconfig`.
#[derive(Debug, Clone)]
pub struct ObliviousDoHConfigs {
    // protocol: length prefix
    configs: Vec<ObliviousDoHConfig>,
}

impl ObliviousDoHConfigs {
    /// Filter the list of configs, leave ones matches ODOH_VERSION.
    pub fn supported(self) -> Vec<ObliviousDoHConfig> {
        self.into_iter().collect()
    }
}

type VecIter = std::vec::IntoIter<ObliviousDoHConfig>;
impl IntoIterator for ObliviousDoHConfigs {
    type Item = ObliviousDoHConfig;
    type IntoIter = std::iter::Filter<VecIter, fn(&Self::Item) -> bool>;

    fn into_iter(self) -> Self::IntoIter {
        self.configs
            .into_iter()
            .filter(|c| c.version == ODOH_VERSION)
    }
}

impl From<Vec<ObliviousDoHConfig>> for ObliviousDoHConfigs {
    fn from(configs: Vec<ObliviousDoHConfig>) -> Self {
        Self { configs }
    }
}

impl Serialize for &ObliviousDoHConfigs {
    fn serialize<B: BufMut>(self, buf: &mut B) -> Result<()> {
        // calculate total length
        let mut len = 0;
        for c in self.configs.iter() {
            // 2 bytes of version and 2 bytes of length
            len += 2 + 2 + c.length;
        }

        buf.put_u16(len);
        for c in self.configs.iter() {
            c.serialize(buf)?;
        }

        Ok(())
    }
}

impl Deserialize for ObliviousDoHConfigs {
    fn deserialize<B: Buf>(buf: &mut B) -> Result<Self> {
        let mut buf = read_lengthed(buf)?;

        let mut configs = Vec::new();
        loop {
            if buf.is_empty() {
                break;
            }
            let c = parse(&mut buf)?;
            configs.push(c);
        }

        Ok(Self { configs })
    }
}

/// Contains version and encryption information. Based on the version specified,
/// the contents can differ.
///
/// For `ODOH_VERSION = 0xff06`, `ObliviousDoHConfig::contents`
/// deserializes into
/// [ObliviousDoHConfigContents](./../struct.ObliviousDoHConfigContents.html).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObliviousDoHConfig {
    version: u16,
    length: u16,
    contents: ObliviousDoHConfigContents,
}

impl Serialize for &ObliviousDoHConfig {
    fn serialize<B: BufMut>(self, buf: &mut B) -> Result<()> {
        buf.put_u16(self.version);
        buf.put_u16(self.length);
        self.contents.serialize(buf)
    }
}

impl Deserialize for ObliviousDoHConfig {
    fn deserialize<B: Buf>(mut buf: &mut B) -> Result<Self> {
        if buf.remaining() < 2 {
            return Err(Error::ShortInput);
        }
        let version = buf.get_u16();
        let mut contents = read_lengthed(&mut buf)?;
        let length = contents.len() as u16;

        Ok(Self {
            version,
            length,
            contents: parse(&mut contents)?,
        })
    }
}

impl From<ObliviousDoHConfig> for ObliviousDoHConfigContents {
    fn from(c: ObliviousDoHConfig) -> Self {
        c.contents
    }
}

impl From<ObliviousDoHConfigContents> for ObliviousDoHConfig {
    fn from(c: ObliviousDoHConfigContents) -> Self {
        Self {
            version: ODOH_VERSION,
            length: c.len() as u16,
            contents: c,
        }
    }
}

/// Contains the HPKE suite parameters and the
/// resolver (target's) public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObliviousDoHConfigContents {
    kem_id: u16,
    kdf_id: u16,
    aead_id: u16,
    // protocol: length prefix
    public_key: Bytes,
}

impl ObliviousDoHConfigContents {
    /// Creates a KeyID for an `ObliviousDoHConfigContents` struct
    fn identifier(&self) -> Result<Vec<u8>> {
        let buf = compose(self)?;

        let key_id_info = LABEL_KEY_ID.to_vec();
        let prk = Hkdf::<<Kdf as KdfTrait>::HashImpl>::new(None, &buf);
        let mut key_id = [0; KDF_OUTPUT_SIZE];
        prk.expand(&key_id_info, &mut key_id)
            .map_err(|_| Error::from(HpkeError::InvalidKdfLength))?;
        Ok(key_id.to_vec())
    }

    fn len(&self) -> usize {
        2 + 2 + 2 + 2 + self.public_key.len()
    }
}

impl Serialize for &ObliviousDoHConfigContents {
    fn serialize<B: BufMut>(self, buf: &mut B) -> Result<()> {
        buf.put_u16(self.kem_id);
        buf.put_u16(self.kdf_id);
        buf.put_u16(self.aead_id);

        buf.put_u16(to_u16(self.public_key.len())?);
        buf.put(self.public_key.clone());
        Ok(())
    }
}

impl Deserialize for ObliviousDoHConfigContents {
    fn deserialize<B: Buf>(mut buf: &mut B) -> Result<Self> {
        if buf.remaining() < 2 + 2 + 2 {
            return Err(Error::ShortInput);
        }

        let kem_id = buf.get_u16();
        let kdf_id = buf.get_u16();
        let aead_id = buf.get_u16();

        if kem_id != KEM_ID || kdf_id != KDF_ID || aead_id != AEAD_ID {
            return Err(Error::InvalidParameter);
        }

        let public_key = read_lengthed(&mut buf)?;
        if public_key.len() != PUBLIC_KEY_SIZE {
            return Err(Error::InvalidInputLength);
        }

        Ok(Self {
            kem_id,
            kdf_id,
            aead_id,
            public_key,
        })
    }
}

/// `ObliviousDoHMessageType` is supplied at the beginning of every ODoH message.
/// It is used to specify whether a message is a query or a response.
#[derive(Debug, Clone, Eq, PartialEq, Copy)]
enum ObliviousDoHMessageType {
    Query = 1,
    Response = 2,
}

impl TryFrom<u8> for ObliviousDoHMessageType {
    type Error = Error;
    fn try_from(n: u8) -> Result<Self> {
        match n {
            1 => Ok(Self::Query),
            2 => Ok(Self::Response),
            _ => Err(Error::InvalidMessageType),
        }
    }
}

/// Main structure used to transfer queries and responses.
///
/// It specifies a message type, an identifier of the corresponding `ObliviousDoHConfigContents`
/// structure being used, and the encrypted message for the target resolver, or a DNS response
/// message for the client.
pub struct ObliviousDoHMessage {
    msg_type: ObliviousDoHMessageType,
    // protocol: length prefix
    key_id: Bytes,
    // protocol: length prefix
    encrypted_msg: Bytes,
}

impl Deserialize for ObliviousDoHMessage {
    fn deserialize<B: Buf>(mut buf: &mut B) -> Result<Self> {
        if !buf.has_remaining() {
            return Err(Error::ShortInput);
        }

        let msg_type = buf.get_u8().try_into()?;
        let key_id = read_lengthed(&mut buf)?;
        let encrypted_msg = read_lengthed(&mut buf)?;

        Ok(Self {
            msg_type,
            key_id,
            encrypted_msg,
        })
    }
}

impl Serialize for &ObliviousDoHMessage {
    fn serialize<B: BufMut>(self, buf: &mut B) -> Result<()> {
        buf.put_u8(self.msg_type as u8);
        buf.put_u16(to_u16(self.key_id.len())?);
        buf.put(self.key_id.clone());
        buf.put_u16(to_u16(self.encrypted_msg.len())?);
        buf.put(self.encrypted_msg.clone());
        Ok(())
    }
}

/// Structure holding unencrypted dns message and padding.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ObliviousDoHMessagePlaintext {
    // protocol: length prefix
    dns_msg: Bytes,
    // protocol: length prefix
    padding: Bytes,
}

impl ObliviousDoHMessagePlaintext {
    /// Create a new [`ObliviousDoHMessagePlaintext`] from DNS message
    /// bytes and an optional padding.
    ///
    /// [`ObliviousDoHMessagePlaintext`]: struct.ObliviousDoHMessagePlaintext.html
    pub fn new<M: AsRef<[u8]>>(msg: M, padding_len: usize) -> Self {
        Self {
            dns_msg: msg.as_ref().to_vec().into(),
            padding: vec![0; padding_len].into(),
        }
    }

    /// Consume the struct, return the inner DNS message bytes.
    pub fn into_msg(self) -> Bytes {
        self.dns_msg
    }
}

impl Deserialize for ObliviousDoHMessagePlaintext {
    fn deserialize<B: Buf>(buf: &mut B) -> Result<Self> {
        let dns_msg = read_lengthed(buf)?;
        let padding = read_lengthed(buf)?;

        if !padding.iter().all(|&x| x == 0x00) {
            return Err(Error::InvalidPadding);
        }

        Ok(Self { dns_msg, padding })
    }
}

impl Serialize for &ObliviousDoHMessagePlaintext {
    fn serialize<B: BufMut>(self, buf: &mut B) -> Result<()> {
        if !self.padding.iter().all(|&x| x == 0x00) {
            return Err(Error::InvalidPadding);
        }

        buf.put_u16(to_u16(self.dns_msg.len())?);
        buf.put(self.dns_msg.clone());

        buf.put_u16(to_u16(self.padding.len())?);
        buf.put(self.padding.clone());

        Ok(())
    }
}

/// `ObliviousDoHKeyPair` supplies relevant encryption/decryption information
/// required by the target resolver to process DNS queries.
pub struct ObliviousDoHKeyPair {
    private_key: <Kex as KeyExchange>::PrivateKey,
    public_key: ObliviousDoHConfigContents,
}

impl ObliviousDoHKeyPair {
    /// Generate a new keypair from given RNG.
    pub fn new<R: RngCore + CryptoRng>(mut rng: &mut R) -> Self {
        let (private_key, public_key) = Kem::gen_keypair(&mut rng);

        let contents = ObliviousDoHConfigContents {
            kem_id: KEM_ID,
            kdf_id: KDF_ID,
            aead_id: AEAD_ID,
            public_key: public_key.to_bytes().to_vec().into(),
        };

        Self {
            private_key,
            public_key: contents,
        }
    }

    /// Return a reference of the private key.
    pub fn private(&self) -> &<Kex as KeyExchange>::PrivateKey {
        &self.private_key
    }

    /// Return a reference of the public key.
    pub fn public(&self) -> &ObliviousDoHConfigContents {
        &self.public_key
    }
}

/// Encrypt a client DNS query with a proper config, return the
/// encrypted query and client secret.
pub fn encrypt_query<R: RngCore + CryptoRng>(
    query: &ObliviousDoHMessagePlaintext,
    config: &ObliviousDoHConfigContents,
    rng: &mut R,
) -> Result<(ObliviousDoHMessage, OdohSecret)> {
    let server_pk =
        <Kex as KeyExchange>::PublicKey::from_bytes(&config.public_key).map_err(Error::from)?;
    let (encapped_key, mut send_ctx) =
        hpke::setup_sender::<Aead, Kdf, Kem, _>(&OpModeS::Base, &server_pk, LABEL_QUERY, rng)
            .map_err(Error::from)?;

    let key_id = config.identifier()?;
    let aad = build_aad(ObliviousDoHMessageType::Query, &key_id)?;

    let mut odoh_secret = OdohSecret::default();
    send_ctx
        .export(LABEL_RESPONSE, &mut odoh_secret)
        .map_err(Error::from)?;

    let mut buf = compose(query)?;

    let tag = send_ctx.seal(&mut buf, &aad).map_err(Error::from)?;

    let result = [
        encapped_key.to_bytes().as_slice(),
        &buf,
        tag.to_bytes().as_slice(),
    ]
    .concat();

    let msg = ObliviousDoHMessage {
        msg_type: ObliviousDoHMessageType::Query,
        key_id: key_id.to_vec().into(),
        encrypted_msg: result.into(),
    };

    Ok((msg, odoh_secret))
}

/// Decrypt a DNS response from the server.
pub fn decrypt_response(
    query: &ObliviousDoHMessagePlaintext,
    response: &ObliviousDoHMessage,
    secret: OdohSecret,
) -> Result<ObliviousDoHMessagePlaintext> {
    if response.msg_type != ObliviousDoHMessageType::Response {
        return Err(Error::InvalidMessageType);
    }

    let response_nonce = response
        .key_id
        .as_ref()
        .try_into()
        .map_err(|_| Error::InvalidResponseNonceLength)?;
    let (key, nonce) = derive_secrets(secret, query, response_nonce)?;
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
    let mut data = response.encrypted_msg.to_vec();

    let aad = build_aad(ObliviousDoHMessageType::Response, &response.key_id)?;

    cipher
        .decrypt_in_place(GenericArray::from_slice(&nonce), &aad, &mut data)
        .map_err(Error::from)?;

    let response_decrypted = parse(&mut Bytes::from(data))?;
    Ok(response_decrypted)
}

/// Decrypt a client query.
pub fn decrypt_query(
    query: &ObliviousDoHMessage,
    key_pair: &ObliviousDoHKeyPair,
) -> Result<(ObliviousDoHMessagePlaintext, OdohSecret)> {
    if query.msg_type != ObliviousDoHMessageType::Query {
        return Err(Error::InvalidMessageType);
    }

    let key_id = key_pair.public().identifier()?;
    let key_id_recv = &query.key_id;

    if !key_id_recv.eq(&key_id) {
        return Err(Error::KeyIdMismatch);
    }

    let server_sk = key_pair.private();
    let key_size = <Kex as KeyExchange>::PublicKey::size();
    let (enc, ct) = query.encrypted_msg.split_at(key_size);

    let encapped_key = EncappedKey::<Kex>::from_bytes(enc).map_err(Error::from)?;

    let mut recv_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &server_sk,
        &encapped_key,
        LABEL_QUERY,
    )
    .map_err(Error::from)?;

    let aad = build_aad(ObliviousDoHMessageType::Query, &key_id)?;

    let (ciphertext, tag_bytes) = ct.split_at(ct.len() - AEAD_TAG_SIZE);
    let mut ciphertext_copy = ciphertext.to_vec();
    let tag = AeadTag::<Aead>::from_bytes(tag_bytes).map_err(Error::from)?;

    recv_ctx
        .open(&mut ciphertext_copy, &aad, &tag)
        .map_err(Error::from)?;

    let mut odoh_secret = OdohSecret::default();
    recv_ctx
        .export(LABEL_RESPONSE, &mut odoh_secret)
        .map_err(Error::from)?;

    let plaintext = ciphertext_copy;

    let query_decrypted = parse(&mut Bytes::from(plaintext))?;
    Ok((query_decrypted, odoh_secret))
}

/// Encrypt a server response.
pub fn encrypt_response(
    query: &ObliviousDoHMessagePlaintext,
    response: &ObliviousDoHMessagePlaintext,
    secret: OdohSecret,
    response_nonce: ResponseNonce,
) -> Result<ObliviousDoHMessage> {
    let (key, nonce) = derive_secrets(secret, query, response_nonce)?;
    let cipher = Aes128Gcm::new(GenericArray::from_slice(&key));
    let aad = build_aad(ObliviousDoHMessageType::Response, &response_nonce)?;

    let mut buf = Vec::new();
    response.serialize(&mut buf)?;
    cipher
        .encrypt_in_place(GenericArray::from_slice(&nonce), &aad, &mut buf)
        .map_err(Error::from)?;

    Ok(ObliviousDoHMessage {
        msg_type: ObliviousDoHMessageType::Response,
        key_id: response_nonce.to_vec().into(),
        encrypted_msg: buf.into(),
    })
}

// TODO: try to use a static buffer for aad building
fn build_aad(t: ObliviousDoHMessageType, key_id: &[u8]) -> Result<Vec<u8>> {
    let mut aad = vec![t as u8];
    aad.extend(&to_u16(key_id.len())?.to_be_bytes());
    aad.extend(key_id);
    Ok(aad)
}

/// Derives a key and nonce pair using the odoh secret and
/// response_nonce.
fn derive_secrets(
    odoh_secret: OdohSecret,
    query: &ObliviousDoHMessagePlaintext,
    response_nonce: ResponseNonce,
) -> Result<(AeadKey, AeadNonce)> {
    let buf = compose(query)?;
    let salt = [
        buf.as_ref(),
        &to_u16(response_nonce.len())?.to_be_bytes(),
        &response_nonce,
    ]
    .concat();

    let h_key = Hkdf::<<Kdf as KdfTrait>::HashImpl>::new(Some(&salt), &odoh_secret);
    let mut key = AeadKey::default();
    h_key
        .expand(LABEL_KEY, &mut key)
        .map_err(|_| Error::from(HpkeError::InvalidKdfLength))?;

    let h_nonce = Hkdf::<<Kdf as KdfTrait>::HashImpl>::new(Some(&salt), &odoh_secret);
    let mut nonce = AeadNonce::default();
    h_nonce
        .expand(LABEL_NONCE, &mut nonce)
        .map_err(|_| Error::from(HpkeError::InvalidKdfLength))?;

    Ok((key, nonce))
}

#[inline]
fn to_u16(n: usize) -> Result<u16> {
    n.try_into().map_err(|_| Error::InvalidInputLength)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    #[test]
    fn configs() {
        // parse
        let configs_hex = "002cff0600280020000100010020bbd80565312cff62c44020a60c511711a6754425d5f42be1de3bca6b9bb3c50f";
        let mut configs_bin: Bytes = hex::decode(configs_hex).unwrap().into();
        let configs: ObliviousDoHConfigs = parse(&mut configs_bin).unwrap();
        assert_eq!(configs.configs.len(), 1);
        // check all bytes have been consumed
        assert!(configs_bin.is_empty());

        // compose
        let buf = compose(&configs).unwrap();
        assert_eq!(configs_hex, hex::encode(&buf));

        // check support
        let mut c1 = configs.configs[0].clone();
        let mut c2 = c1.clone();
        c1.version = 0x00;
        let supported = ObliviousDoHConfigs::from(vec![c1.clone(), c2.clone()]).supported();
        assert_eq!(supported[0], c2);

        c2.version = 0x01;
        let supported = ObliviousDoHConfigs::from(vec![c1.clone(), c2.clone()]).supported();
        assert!(supported.is_empty());
    }

    #[test]
    fn pubkey() {
        // parse
        let key_hex =
            "0020000100010020aacc53b3df0c6eb2d7d5ce4ddf399593376c9903ba6a52a52c3a2340f97bb764";
        let mut key_bin: Bytes = hex::decode(key_hex).unwrap().into();
        let key: ObliviousDoHConfigContents = parse(&mut key_bin).unwrap();
        assert!(key_bin.is_empty());

        // compose
        let buf = compose(&key).unwrap();
        assert_eq!(key_hex, hex::encode(&buf));
    }

    #[test]
    fn exchange() {
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
        let config_contents = client_configs.supported()[0].clone().into();

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
    }

    #[test]
    fn test_vector() {
        use super::*;
        use serde::Deserialize as SerdeDeserialize;

        const TEST_VECTORS: &str = std::include_str!("../tests/test-vectors.json");

        #[derive(SerdeDeserialize, Debug, Clone)]
        pub struct TestVector {
            pub aead_id: u16,
            pub kdf_id: u16,
            pub kem_id: u16,
            pub key_id: String,
            pub odohconfigs: String,
            pub public_key_seed: String,
            pub transactions: Vec<Transaction>,
        }

        #[derive(SerdeDeserialize, Debug, Clone)]
        #[serde(rename_all = "camelCase")]
        pub struct Transaction {
            pub oblivious_query: String,
            pub oblivious_response: String,
            pub query: String,
            pub response: String,
            pub query_padding_length: usize,
            pub response_padding_length: usize,
        }

        let test_vectors: Vec<TestVector> = serde_json::from_str(TEST_VECTORS).unwrap();
        for tv in test_vectors {
            let ikm_bytes = hex::decode(tv.public_key_seed).unwrap();
            let (secret_key, _) = Kem::derive_keypair(&ikm_bytes);

            let mut configs_bytes: Bytes = hex::decode(tv.odohconfigs).unwrap().into();
            let configs: ObliviousDoHConfigs = parse(&mut configs_bytes).unwrap();
            let odoh_public_key: ObliviousDoHConfigContents =
                configs.supported().into_iter().next().unwrap().into();

            assert_eq!(
                odoh_public_key.identifier().unwrap(),
                hex::decode(tv.key_id).unwrap(),
            );

            let key_pair = ObliviousDoHKeyPair {
                private_key: secret_key,
                public_key: odoh_public_key,
            };

            for t in tv.transactions {
                let query = ObliviousDoHMessagePlaintext::new(
                    &hex::decode(t.query).unwrap(),
                    t.query_padding_length,
                );

                let mut odoh_query_bytes: Bytes = hex::decode(t.oblivious_query).unwrap().into();
                let odoh_query = parse(&mut odoh_query_bytes).unwrap();

                // decrypt oblivious_query from test should match its query
                let (odoh_query_dec, srv_secret) = decrypt_query(&odoh_query, &key_pair).unwrap();
                assert_eq!(odoh_query_dec, query);

                let odoh_response_bytes: Bytes = hex::decode(t.oblivious_response).unwrap().into();
                let odoh_response: ObliviousDoHMessage =
                    parse(&mut odoh_response_bytes.clone()).unwrap();

                let response = ObliviousDoHMessagePlaintext::new(
                    &hex::decode(t.response).unwrap(),
                    t.response_padding_length,
                );

                // assert with fixed response nonce to make sure the
                // right hpke version is being used
                let response_enc = encrypt_response(
                    &query,
                    &response,
                    srv_secret,
                    odoh_response.key_id[..16].try_into().unwrap(),
                )
                .unwrap();

                // encrypted response is the same as the one parsed from test
                let response_enc_bytes = compose(&response_enc).unwrap();
                assert_eq!(response_enc_bytes.as_ref(), odoh_response_bytes.as_ref(),);
            }
        }
    }
}

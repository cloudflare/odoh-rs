//! API for protocol functionality such as creating and parsing ODoH queries and responses.

use anyhow::{anyhow, Result};
use bincode2::LengthOption;
use hkdf::Hkdf;
use hpke::{
    aead::{AeadTag, AesGcm128},
    kdf::HkdfSha256,
    kdf::Kdf as KdfTrait,
    kem::X25519HkdfSha256,
    kex::KeyExchange,
    AeadCtxR, Deserializable, EncappedKey, Kem as KemTrait, OpModeR, OpModeS, Serializable,
};
use lazy_static::lazy_static;
use rand::{rngs::StdRng, SeedableRng};
use ring::aead::{Aad, Algorithm, LessSafeKey, Nonce, UnboundKey, AES_128_GCM};
use serde::{Deserialize as SerdeDeserialize, Serialize as SerdeSerialize};
use serde_repr::*;
use std::convert::{TryFrom, TryInto};

/// HTTP header required for sending queries and responses
pub const ODOH_HTTP_HEADER: &str = "application/oblivious-dns-message";
const LABEL_QUERY: &[u8] = b"odoh query";
const LABEL_KEY: &[u8] = b"odoh key";
const LABEL_NONCE: &[u8] = b"odoh nonce";
const LABEL_KEY_ID: &[u8] = b"odoh key id";
const LABEL_SECRET: &[u8] = b"odoh secret";
const ODOH_SECRET_LEN: usize = 32;
const RESPONSE_AAD: &[u8] = &[2u8, 0, 0];
/// ODoH version supported by this library
pub const ODOH_VERSION: u16 = 0xff02;

/// CHANGE THESE values for supporting other suites
pub type Kem = X25519HkdfSha256;
pub type Aead = AesGcm128;
pub type Kdf = HkdfSha256;
pub type Kex = <Kem as KemTrait>::Kex;
const KEM_ID: u16 = 0x0020;
const KDF_ID: u16 = 0x0001;
const AEAD_ID: u16 = 0x0001;

/// For the selected KDF: SHA256
/// CHANGE THIS for different KDF
const KDF_OUTPUT_SIZE: usize = 32;

lazy_static! {
    /// CHANGE THIS for different Aead
    static ref AEAD_ALGORITHM: &'static Algorithm = {
        &AES_128_GCM
    };
    static ref AEAD_KEY_SIZE: usize = {
        AEAD_ALGORITHM.key_len()
    };
    static ref AEAD_NONCE_SIZE: usize = {
        AEAD_ALGORITHM.nonce_len()
    };
    static ref AEAD_TAG_SIZE: usize = {
        AEAD_ALGORITHM.tag_len()
    };
}

macro_rules! impl_custom_serde {
    ($name:ident) => {
        impl Serialize for $name {}
        impl<'de> Deserialize<'de> for $name {}
    };
}

/// Serialize to IETF wireformat that is similar to [XDR](https://tools.ietf.org/html/rfc1014)
pub trait Serialize {
    fn to_bytes(&self) -> Result<Vec<u8>>
    where
        Self: SerdeSerialize,
    {
        let serialized = bincode2::config()
            .big_endian()
            .array_length(LengthOption::U16)
            .serialize(&self)?;
        Ok(serialized)
    }
}
/// Deserialize from IETF wireformat that is similar to [XDR](https://tools.ietf.org/html/rfc1014)
pub trait Deserialize<'de> {
    fn from_bytes(buf: &'de [u8]) -> Result<Self>
    where
        Self: Sized,
        Self: SerdeDeserialize<'de>,
    {
        let deserialized: Self = bincode2::config()
            .big_endian()
            .array_length(LengthOption::U16)
            .deserialize(buf)?;
        Ok(deserialized)
    }
}
/// Supplies config information to the client.
///
/// It contains one or more `ObliviousDoHConfig` structures in
/// decreasing order of preference. This allows a server to support multiple versions
/// of ODoH and multiple sets of ODoH HPKE suite parameters.
///
/// This information is designed to be disseminated via [DNS HTTPS records](https://tools.ietf.org/html/draft-ietf-dnsop-svcb-httpssvc-03), using the
/// param `odohconfig`.
#[derive(SerdeSerialize, SerdeDeserialize, Clone, Debug)]
pub struct ObliviousDoHConfigs {
    pub configs: Vec<ObliviousDoHConfig>,
}

#[doc(hidden)]
impl ObliviousDoHConfigs {
    pub fn to_bytes(&self) -> Result<Vec<u8>> {
        let mut serialized: Vec<u8> = self
            .configs
            .iter()
            .map(|c| c.to_bytes().unwrap())
            .flatten()
            .collect();
        let length = (serialized.len() as u16).to_be_bytes();
        serialized.splice(0..0, length.iter().cloned());
        Ok(serialized)
    }

    pub fn from_bytes(buf: &[u8]) -> Result<Self> {
        let length_bytes: [u8; 2] = buf[0..2].try_into()?;
        let length = u16::from_be_bytes(length_bytes) as usize;
        let mut bytes_left = buf
            .get(2..2 + length)
            .ok_or_else(|| anyhow!("ObliviousDoHConfigs length is too short"))?;
        let mut configs = Vec::new();
        while bytes_left.len() > 1 {
            let config = ObliviousDoHConfig::from_bytes(bytes_left)?;
            configs.push(config.clone());
            let byte_offset = config.contents.len() + 4;
            bytes_left = &bytes_left
                .get(byte_offset..)
                .ok_or_else(|| anyhow!("ObliviousDoHConfigs could not be deserialized"))?;
        }
        Ok(Self { configs })
    }
}

/// Contains version and encryption information. Based on the version specified,
/// the contents can differ.
///
/// For `ODOH_VERSION = 0xff02`, `ObliviousDoHConfig::contents` deserializes into [ObliviousDoHConfigContents](./../struct.ObliviousDoHConfigContents.html).
#[derive(SerdeSerialize, SerdeDeserialize, Clone, Debug)]
pub struct ObliviousDoHConfig {
    pub version: u16,
    pub contents: Vec<u8>,
}
impl_custom_serde!(ObliviousDoHConfig);

impl ObliviousDoHConfig {
    /// Creates a new `ObliviousDoHConfig` containing the library version and contents, after
    /// validating that contents correspond to a supported HPKE suite.
    pub fn new(buf: &[u8]) -> Result<Self> {
        let contents = ObliviousDoHConfigContents::from_bytes(buf)?;
        contents.assert_validity()?;
        Ok(ObliviousDoHConfig {
            version: ODOH_VERSION,
            contents: buf.to_vec(),
        })
    }
}

/// Contains the HPKE suite parameters and the
/// resolver (target's) public key.
#[derive(SerdeSerialize, SerdeDeserialize, Clone, Debug)]
pub struct ObliviousDoHConfigContents {
    pub kem_id: u16,
    pub kdf_id: u16,
    pub aead_id: u16,
    pub public_key: Vec<u8>,
}
impl_custom_serde!(ObliviousDoHConfigContents);

impl ObliviousDoHConfigContents {
    /// Creates a KeyID for an `ObliviousDoHConfigContents` struct
    pub fn identifier(&self) -> Vec<u8> {
        let serialized = self.to_bytes().unwrap();
        Self::identifier_from_bytes(&serialized)
    }

    /// Creates a KeyID from a serialized `ObliviousDoHConfigContents`
    /// Use this when you already have a serialized `ObliviousDoHConfigContents`
    pub fn identifier_from_bytes(key: &[u8]) -> Vec<u8> {
        let key_id_info = LABEL_KEY_ID.to_vec();
        let prk = Hkdf::<<Kdf as KdfTrait>::HashImpl>::new(None, key);
        let mut key_id = [0; KDF_OUTPUT_SIZE];
        prk.expand(&key_id_info, &mut key_id).unwrap();
        key_id.to_vec()
    }

    /// Asserts that the HPKE suite corresponds to the supported HPKE suite
    pub fn assert_validity(&self) -> Result<()> {
        let valid = (self.kem_id == KEM_ID)
            && (self.kdf_id == KDF_ID)
            && (self.aead_id == AEAD_ID)
            && (self.public_key.len() == <Kex as KeyExchange>::PublicKey::size());
        match valid {
            true => Ok(()),
            false => Err(anyhow!("HPKE suite is invalid")),
        }
    }
}

// `ObliviousDoHKeyPair` supplies relevant encryption/decryption information
// required by the target resolver to process DNS queries.
pub struct ObliviousDoHKeyPair {
    pub private_key: <Kex as KeyExchange>::PrivateKey,
    pub public_key: ObliviousDoHConfigContents,
}

/// `ObliviousDoHMessageType` is supplied at the beginning of every ODoH message.
/// It is used to specify whether a message is a query or a response.
#[derive(Serialize_repr, Deserialize_repr, Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ObliviousDoHMessageType {
    Query = 1,
    Response = 2,
}

/// Main structure used to transfer queries and responses.
///
/// It specifies a message type, an identifier of the corresponding `ObliviousDoHConfigContents`
/// structure being used, and the encrypted message for the target resolver, or a DNS response
/// message for the client.
#[derive(SerdeSerialize, SerdeDeserialize, Clone, Debug)]
pub struct ObliviousDoHMessage {
    pub msg_type: ObliviousDoHMessageType,
    pub key_id: Vec<u8>,
    pub encrypted_msg: Vec<u8>,
}
impl_custom_serde!(ObliviousDoHMessage);

impl ObliviousDoHMessage {
    /// Creates a new `ObliviousDoHMessage` based on the type of message.
    /// When the key is not specified, which is the case for `ObliviousDoHMessageType::Response`,
    /// it sets the key id to be an empty vector, otherwise it computes the key ID.
    pub fn new(
        msg_type: ObliviousDoHMessageType,
        key: Option<ObliviousDoHConfigContents>,
        msg: Vec<u8>,
    ) -> Self {
        let key_id;
        if let Some(k) = key {
            key_id = k.identifier();
        } else {
            key_id = vec![];
        }
        Self {
            msg_type,
            key_id,
            encrypted_msg: msg,
        }
    }
}

/// Interface for raw queries and responses
pub trait ObliviousDoHMessagePlaintext {
    fn padding(&self) -> &[u8];

    /// According to the ODoH draft, the padding is required to be all zeros.
    /// This function ensures that is the case.
    ///
    /// Note that this is NOT constant time.
    fn validate_padding(&self) -> Result<()> {
        if !self.padding().iter().all(|&x| x == 0) {
            return Err(anyhow!("Padding is not all zeros"));
        }
        Ok(())
    }
}

/// Contains the raw dns query from client and associated padding
#[derive(SerdeSerialize, SerdeDeserialize, Clone, Debug)]
pub struct ObliviousDoHQueryBody {
    pub dns_msg: Vec<u8>,
    pub padding: Vec<u8>,
}
impl_custom_serde!(ObliviousDoHQueryBody);

impl ObliviousDoHMessagePlaintext for ObliviousDoHQueryBody {
    fn padding(&self) -> &[u8] {
        &self.padding
    }
}

impl ObliviousDoHQueryBody {
    /// Creates an `ObliviousDoHQueryBody` from a raw `dns_msg` and an optional padding length.
    /// If padding length is `None`, uses the default padding.
    pub fn new(dns_msg: &[u8], padding_len: Option<usize>) -> Self {
        let padding;
        match padding_len {
            Some(len) => padding = vec![0; len],
            None => padding = vec![],
        };
        Self {
            dns_msg: dns_msg.to_vec(),
            padding,
        }
    }
}

/// Contains the raw dns response from resolver and associated padding
#[derive(SerdeSerialize, SerdeDeserialize, Clone, Debug)]
pub struct ObliviousDoHResponseBody {
    pub dns_msg: Vec<u8>,
    pub padding: Vec<u8>,
}
impl_custom_serde!(ObliviousDoHResponseBody);

impl ObliviousDoHMessagePlaintext for ObliviousDoHResponseBody {
    fn padding(&self) -> &[u8] {
        &self.padding
    }
}

/// Derives a key and nonce pair using the odoh secret
fn derive_secrets(
    odoh_secret: &[u8],
    query: &ObliviousDoHQueryBody,
) -> Result<(LessSafeKey, Nonce)> {
    let key_info = LABEL_KEY.to_vec();
    let nonce_info = LABEL_NONCE.to_vec();
    let query_bytes = query.to_bytes().unwrap();

    let h_key = Hkdf::<<Kdf as KdfTrait>::HashImpl>::new(Some(&query_bytes), &odoh_secret);
    let mut key = vec![0; *AEAD_KEY_SIZE];
    h_key.expand(&key_info, &mut key).unwrap();

    let h_nonce = Hkdf::<<Kdf as KdfTrait>::HashImpl>::new(Some(&query_bytes), &odoh_secret);
    let mut nonce = vec![0; *AEAD_NONCE_SIZE];
    h_nonce.expand(&nonce_info, &mut nonce).unwrap();
    let answer_key = LessSafeKey::new(UnboundKey::new(&AEAD_ALGORITHM, &key).unwrap());
    let answer_nonce = Nonce::try_assume_unique_for_key(&nonce).unwrap();

    Ok((answer_key, answer_nonce))
}

fn build_query_aad(server_config: &ObliviousDoHConfigContents) -> Vec<u8> {
    let key_id = server_config.identifier();
    let key_id_len = key_id.len();
    let key_size_as_u16 = u16::try_from(key_id_len).unwrap().to_be_bytes();

    let mut aad = vec![ObliviousDoHMessageType::Query as u8];
    aad.extend(&key_size_as_u16);
    aad.extend(key_id);
    aad
}

fn encrypt_query_helper(
    server_config: &ObliviousDoHConfigContents,
    query_body: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    let server_pk = <Kex as KeyExchange>::PublicKey::from_bytes(&server_config.public_key)
        .expect("could not deserialize server public key");

    let mut csprng = StdRng::from_entropy();

    let (encapped_key, mut client_ctx) = hpke::setup_sender::<Aead, Kdf, Kem, _>(
        &OpModeS::Base,
        &server_pk,
        LABEL_QUERY,
        &mut csprng,
    )
    .expect("invalid server pubkey");

    let mut msg_copy = query_body.to_vec();
    let query_aad = build_query_aad(server_config);
    let tag = client_ctx
        .seal(&mut msg_copy, &query_aad)
        .expect("encryption failed");
    let mut odoh_secret = [0; ODOH_SECRET_LEN];
    client_ctx.export(LABEL_SECRET, &mut odoh_secret).unwrap();

    let ciphertext = msg_copy.to_vec();
    let result = [
        encapped_key.to_bytes().as_slice(),
        &ciphertext,
        tag.to_bytes().as_slice(),
    ]
    .concat();
    Ok((result, odoh_secret.to_vec()))
}

/// Decrypts a message `msg` using the private key from the HPKE `key_pair`
/// In practice, this is used to decrypt the encrypted query sent by the client
async fn decrypt_query_helper(
    server_ctx: &mut AeadCtxR<Aead, Kdf, Kem>,
    server_config: &ObliviousDoHConfigContents,
    query_ciphertext: Vec<u8>,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let aad = build_query_aad(server_config);
    let (ciphertext, tag_bytes) =
        query_ciphertext.split_at(query_ciphertext.len() - *AEAD_TAG_SIZE);
    let mut ciphertext_copy = ciphertext.to_vec();

    let tag = AeadTag::<Aead>::from_bytes(tag_bytes).unwrap();

    server_ctx
        .open(&mut ciphertext_copy, &aad, &tag)
        .expect("invalid ciphertext");

    let mut odoh_secret = [0; ODOH_SECRET_LEN];
    server_ctx.export(LABEL_SECRET, &mut odoh_secret).unwrap();

    let plaintext = ciphertext_copy.to_vec();
    Ok((plaintext, odoh_secret.to_vec()))
}

/// encrypted_query_msg is ObliviousDoHMessage.encrypted_msg.
/// Returns the ciphertext to decrypt, and the server context
fn setup_query_context(
    key_pair: &ObliviousDoHKeyPair,
    encrypted_query_msg: Vec<u8>,
) -> (Vec<u8>, AeadCtxR<Aead, Kdf, Kem>) {
    let server_sk = &key_pair.private_key;

    let key_size = <Kex as KeyExchange>::PublicKey::size();
    let (enc, ct) = encrypted_query_msg.split_at(key_size);

    let encapped_key =
        EncappedKey::<Kex>::from_bytes(enc).expect("could not deserialize the encapsulated pubkey");

    let recv_ctx = hpke::setup_receiver::<Aead, Kdf, Kem>(
        &OpModeR::Base,
        &server_sk,
        &encapped_key,
        LABEL_QUERY,
    )
    .expect("failed to setup receiver");

    (ct.to_vec(), recv_ctx)
}

/// Encrypts a message `msg` using the symmetric key derived from query
/// In practice, this is used to encrypt the response body before sending
/// to client
async fn encrypt_response_helper(
    odoh_secret: &[u8],
    plaintext_resp_body: &[u8],
    query: &ObliviousDoHQueryBody,
) -> Result<Vec<u8>> {
    let aad = Aad::from(RESPONSE_AAD);
    let (key, nonce) = derive_secrets(odoh_secret, query).unwrap();
    let mut data = plaintext_resp_body.to_owned();
    key.seal_in_place_append_tag(nonce, aad, &mut data).unwrap();
    Ok(data.to_vec())
}

/// Decrypts a response `resp` using the symmetric key derived from query
/// In practice, this is used to decrypt the encrypted response body (as bytes)
/// which is received by the client
fn decrypt_response_helper(
    odoh_secret: &[u8],
    encrypted_resp_body: &[u8],
    query: &ObliviousDoHQueryBody,
) -> Result<Vec<u8>> {
    let aad = Aad::from(RESPONSE_AAD);
    let (key, nonce) = derive_secrets(odoh_secret, query).unwrap();
    let mut data = encrypted_resp_body.to_owned();
    let plaintext = key.open_in_place(nonce, aad, &mut data).unwrap();
    Ok(plaintext.to_vec())
}

/// Returns the config supported by the library from a buffer containing `odohconfigs`.
///
/// `odohconfigs` is distributed by the server, and the client calls this function
/// in order to retrieve a supported config that it can use to encrypt queries to the server.
pub fn get_supported_config(odohconfigs: &[u8]) -> Result<ObliviousDoHConfigContents> {
    let configs = ObliviousDoHConfigs::from_bytes(odohconfigs)?.configs;
    let supported_config = configs
        .iter()
        .find(|&c| c.version == ODOH_VERSION)
        .ok_or_else(|| anyhow!("No supported config"))?;
    ObliviousDoHConfigContents::from_bytes(&supported_config.contents)
}

/// Create a query to send to the server, and
/// a client secret from exporting the client context.
///
/// Returns `(ObliviousDoHMessage.to_bytes(), client secret)`.
pub fn create_query_msg(
    server_config: &ObliviousDoHConfigContents,
    query: &ObliviousDoHQueryBody,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let (encrypted_msg, client_secret) = encrypt_query_helper(server_config, &query.to_bytes()?)?;
    Ok((
        ObliviousDoHMessage {
            msg_type: ObliviousDoHMessageType::Query,
            key_id: server_config.identifier(),
            encrypted_msg,
        }
        .to_bytes()
        .unwrap(),
        client_secret,
    ))
}

/// Parse bytes into a valid `ObliviousDoHResponseBody` struct,
/// used by the client when it receives `resp_msg` from server
pub fn parse_received_response(
    client_secret: &[u8],
    odoh_encrypted_resp_msg: &[u8],
    query: &ObliviousDoHQueryBody,
) -> Result<ObliviousDoHResponseBody> {
    let de_resp = ObliviousDoHMessage::from_bytes(odoh_encrypted_resp_msg)?;

    if de_resp.msg_type != ObliviousDoHMessageType::Response {
        return Err(anyhow!("ObliviousDoHMessageType is wrong"));
    }

    if !de_resp.key_id.is_empty() {
        return Err(anyhow!("KeyID for response is not empty"));
    }

    let decrypted_msg = decrypt_response_helper(client_secret, &de_resp.encrypted_msg, query)?;
    let response_body = ObliviousDoHResponseBody::from_bytes(&decrypted_msg)?;
    response_body.validate_padding()?;
    Ok(response_body)
}

/// Deserializes, validates and decrypts the query sent by the client to generate
/// an `ObliviousDoHQueryBody` that will be used by the resolver to generate a response.
///
/// It also checks if the key id of the query matches the key id of the server,
/// discarding the message if that isn't the case.
///
/// `odoh_encrypted_query_msg` = `ObliviousDoHMessage.to_bytes()`
///
/// Returns `query_body` and `server_secret` generated from `server_ctx`.
pub async fn parse_received_query(
    key_pair: &ObliviousDoHKeyPair,
    odoh_encrypted_query_msg: &[u8],
) -> Result<(ObliviousDoHQueryBody, Vec<u8>)> {
    let de_query = ObliviousDoHMessage::from_bytes(odoh_encrypted_query_msg)?;

    if de_query.msg_type != ObliviousDoHMessageType::Query {
        return Err(anyhow!("ObliviousDoHMessageType is wrong"));
    }

    let key_id = key_pair.public_key.identifier();
    let key_id_recv = de_query.key_id;

    if !key_id.eq(&key_id_recv) {
        return Err(anyhow!("KeyId of query differs from expected KeyID"));
    }

    let encrypted_query_msg = de_query.encrypted_msg;
    let (ciphertext, mut server_ctx) = setup_query_context(key_pair, encrypted_query_msg);
    let (decrypted_msg, server_secret) =
        decrypt_query_helper(&mut server_ctx, &key_pair.public_key, ciphertext).await?;
    let query = ObliviousDoHQueryBody::from_bytes(&decrypted_msg)?;
    query.validate_padding()?;
    Ok((query, server_secret))
}

/// This function creates an `ObliviousDoHResponseBody` from the DNS response `resolver_resp` sent by the
/// resolver. It then encrypts this response body, creates an `ObliviousDoHMessage` and serializes it.
///
/// This serialized `ObliviousDoHMessage` is sent to the client.
///
/// `resolver_resp` refers to plain dns response from the resolver,
/// `server_secret` is the server context secret
pub async fn create_response_msg(
    server_secret: &[u8],
    resolver_resp: &[u8],
    padding_len: Option<usize>,
    query: &ObliviousDoHQueryBody,
) -> Result<Vec<u8>> {
    let padding;
    match padding_len {
        Some(len) => padding = vec![0; len],
        None => padding = vec![],
    };
    let response_body = ObliviousDoHResponseBody {
        dns_msg: resolver_resp.to_vec(),
        padding,
    }
    .to_bytes()?;
    let encrypted_resp = encrypt_response_helper(server_secret, &response_body, query).await?;

    ObliviousDoHMessage::new(ObliviousDoHMessageType::Response, None, encrypted_resp).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex;
    use std::fs::File;
    use std::io::BufReader;

    const TEST_VECTORS_FILE_PATH: &str = "tests/test-vectors.json";

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

    fn parse_test_vectors() -> Result<Vec<TestVector>> {
        let file = File::open(TEST_VECTORS_FILE_PATH)?;
        let reader = BufReader::new(file);
        let test_vectors: Vec<TestVector> = serde_json::from_reader(reader)?;
        Ok(test_vectors)
    }

    fn generate_key_pair() -> ObliviousDoHKeyPair {
        let ikm = "871389a8727130974e3eb3ee528d440a871389a8727130974e3eb3ee528d440a";
        let ikm_bytes = hex::decode(ikm).unwrap();
        let (secret_key, public_key) = Kem::derive_keypair(&ikm_bytes);
        let public_key_bytes = public_key.to_bytes().to_vec();
        let odoh_public_key = ObliviousDoHConfigContents {
            kem_id: 0x0020,
            kdf_id: 0x0001,
            aead_id: 0x0001,
            public_key: public_key_bytes,
        };
        ObliviousDoHKeyPair {
            private_key: secret_key,
            public_key: odoh_public_key,
        }
    }

    fn generate_query_body() -> ObliviousDoHQueryBody {
        ObliviousDoHQueryBody::new(
            &hex::decode("5513010000010000000000000377777706676f6f676c6503636f6d00001c0001")
                .unwrap(),
            None,
        )
    }

    #[tokio::test]
    async fn test_query_encryption_decryption() {
        let key_pair = generate_key_pair();
        let query = generate_query_body();
        let (oblivious_query, _) = create_query_msg(&key_pair.public_key, &query).unwrap();
        let (parsed_query, _) = parse_received_query(&key_pair, &oblivious_query)
            .await
            .unwrap();
        assert_eq!(query.to_bytes().unwrap(), parsed_query.to_bytes().unwrap());
    }

    #[tokio::test]
    async fn test_response_encryption_decryption() {
        let key_pair = generate_key_pair();
        let query = generate_query_body();
        let (oblivious_query, client_secret) =
            create_query_msg(&key_pair.public_key, &query).unwrap();
        let (_, server_secret) = parse_received_query(&key_pair, &oblivious_query)
            .await
            .unwrap();
        let resp = ObliviousDoHResponseBody {
            dns_msg: vec![1u8, 2, 3, 4, 5, 6],
            padding: vec![],
        };
        let generated_resp = create_response_msg(&server_secret, &resp.dns_msg, None, &query)
            .await
            .unwrap();
        let parsed_resp = parse_received_response(&client_secret, &generated_resp, &query).unwrap();
        assert_eq!(parsed_resp.to_bytes().unwrap(), resp.to_bytes().unwrap());
    }

    /// Tests interop with `odoh-go`
    /// This test will fail if the ciphersuite of this library is not the following:
    /// (X25519HkdfSha256, AesGcm128, HkdfSha256) because of the test vector config
    /// Test vectors are specified in tests/test-vectors.json
    #[tokio::test]
    async fn test_vectors_for_odoh() {
        let test_vectors = parse_test_vectors().unwrap();
        for tv in test_vectors {
            let ikm_bytes = hex::decode(tv.public_key_seed).unwrap();
            let (secret_key, _) = Kem::derive_keypair(&ikm_bytes);
            let expected_public_key_id = hex::decode(tv.key_id).unwrap();
            let odoh_public_key =
                get_supported_config(&hex::decode(tv.odohconfigs).unwrap()).unwrap();

            assert_eq!(odoh_public_key.identifier(), expected_public_key_id);

            let key_pair = ObliviousDoHKeyPair {
                private_key: secret_key,
                public_key: odoh_public_key,
            };

            for t in tv.transactions {
                let query = ObliviousDoHQueryBody::new(
                    &hex::decode(t.query).unwrap(),
                    Some(t.query_padding_length),
                );
                let (host_oblivious_query, host_client_secret) =
                    create_query_msg(&key_pair.public_key, &query).unwrap();
                let remote_oblivious_query = hex::decode(t.oblivious_query).unwrap();

                // Decrypted remote_encrypted_msg should match decrypted host_encrypted_msg
                let (host_parsed_query, host_server_secret) =
                    parse_received_query(&key_pair, &host_oblivious_query)
                        .await
                        .unwrap();
                assert_eq!(
                    host_parsed_query.to_bytes().unwrap(),
                    query.to_bytes().unwrap()
                );

                let (remote_parsed_query, remote_server_secret) =
                    parse_received_query(&key_pair, &remote_oblivious_query)
                        .await
                        .unwrap();
                assert_eq!(
                    host_parsed_query.to_bytes().unwrap(),
                    remote_parsed_query.to_bytes().unwrap()
                );

                let resolver_resp = hex::decode(t.response).unwrap();
                let host_generated_response = create_response_msg(
                    &host_server_secret,
                    &resolver_resp,
                    Some(t.response_padding_length),
                    &query,
                )
                .await
                .unwrap();
                let remote_generated_response = create_response_msg(
                    &remote_server_secret,
                    &resolver_resp,
                    Some(t.response_padding_length),
                    &query,
                )
                .await
                .unwrap();
                let remote_oblivious_response = hex::decode(t.oblivious_response).unwrap();

                assert_eq!(remote_generated_response, remote_oblivious_response);

                let host_parsed_response =
                    parse_received_response(&host_client_secret, &host_generated_response, &query)
                        .unwrap();
                assert_eq!(host_parsed_response.dns_msg, resolver_resp);
            }
        }
    }

    #[tokio::test]
    async fn test_configs() {
        let config_contents1 = ObliviousDoHConfigContents {
            kem_id: 0x0020,
            kdf_id: 0x3300,
            aead_id: 0x4456,
            public_key: vec![1, 32, 4, 5, 7],
        }
        .to_bytes()
        .unwrap();
        let config1 = ObliviousDoHConfig {
            version: 0xff02,
            contents: config_contents1.clone(),
        };
        let config2 = ObliviousDoHConfig {
            version: 0xff03,
            contents: ObliviousDoHConfigContents {
                kem_id: 0x0020,
                kdf_id: 0x3300,
                aead_id: 0x4456,
                public_key: vec![1, 32, 4, 5, 7, 8, 9],
            }
            .to_bytes()
            .unwrap(),
        };
        let configs = ObliviousDoHConfigs {
            configs: vec![config2.clone(), config1.clone(), config2.clone()],
        }
        .to_bytes()
        .unwrap();
        let expected_configs = vec![
            0, 55, 255, 3, 0, 15, 0, 32, 51, 0, 68, 86, 0, 7, 1, 32, 4, 5, 7, 8, 9, 255, 2, 0, 13,
            0, 32, 51, 0, 68, 86, 0, 5, 1, 32, 4, 5, 7, 255, 3, 0, 15, 0, 32, 51, 0, 68, 86, 0, 7,
            1, 32, 4, 5, 7, 8, 9,
        ];
        assert_eq!(configs, expected_configs);

        let supported_config = get_supported_config(&expected_configs).unwrap();
        assert_eq!(supported_config.to_bytes().unwrap(), config_contents1);

        // Assert `get_supported_config` fails when no supported configs are found
        let config3 = ObliviousDoHConfig {
            version: 0xff04,
            contents: ObliviousDoHConfigContents {
                kem_id: 0x0021,
                kdf_id: 0x3300,
                aead_id: 0x4456,
                public_key: vec![1, 32, 4, 5, 7, 8, 9, 10],
            }
            .to_bytes()
            .unwrap(),
        };

        let configs_err = ObliviousDoHConfigs {
            configs: vec![config2.clone(), config3.clone()],
        }
        .to_bytes()
        .unwrap();

        assert_eq!(get_supported_config(&configs_err).is_err(), true);
    }
}

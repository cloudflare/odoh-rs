use criterion::{black_box, criterion_group, criterion_main, Criterion};
use hpke::Serializable;
use odoh_rs::key_utils::*;
use odoh_rs::protocol::*;

fn generate_key_pair() -> ObliviousDoHKeyPair {
    let ikm = "871389a8727130974e3eb3ee528d440a871389a8727130974e3eb3ee528d440a";
    let ikm_bytes = hex::decode(ikm).unwrap();
    let (secret_key, public_key) = derive_keypair_from_seed(&ikm_bytes);
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
        &hex::decode("5513010000010000000000000377777706676f6f676c6503636f6d00001c0001").unwrap(),
        None,
    )
}

pub fn bench_parse_query(c: &mut Criterion) {
    let key_pair = generate_key_pair();
    let query = generate_query_body();
    let (oblivious_query, _) = create_query_msg(&key_pair.public_key, &query).unwrap();
    c.bench_function("parse_received_query", |b| {
        b.iter(|| black_box(parse_received_query(&key_pair, &oblivious_query)))
    });
}

pub fn bench_parse_response(c: &mut Criterion) {
    let client_secret = vec![
        185, 1, 153, 19, 244, 146, 251, 107, 66, 227, 209, 137, 191, 128, 219, 44, 12, 154, 195,
        137, 220, 77, 86, 149, 207, 128, 202, 85, 85, 182, 171, 215,
    ];
    let generated_resp = vec![
        2, 0, 0, 0, 26, 165, 223, 11, 24, 56, 158, 31, 166, 11, 144, 56, 129, 76, 247, 176, 49,
        168, 168, 106, 68, 188, 192, 104, 89, 213, 9,
    ];
    let query = generate_query_body();
    c.bench_function("parse_received_response", |b| {
        b.iter(|| {
            black_box(parse_received_response(
                &client_secret,
                &generated_resp,
                &query,
            ))
        })
    });
}

criterion_group!(benches, bench_parse_query, bench_parse_response);
criterion_main!(benches);

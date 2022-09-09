use criterion::{black_box, criterion_group, criterion_main, Criterion};
use odoh_rs::*;
use rand::rngs::StdRng;
use rand::SeedableRng;

pub fn bench_steps(c: &mut Criterion) {
    // generate all the data for this test
    let mut rng = StdRng::from_seed([0; 32]);
    let key_pair = ObliviousDoHKeyPair::new(&mut rng);

    let query = ObliviousDoHMessagePlaintext::new(b"What's the IP of one.one.one.one?", 0);
    let query_bytes = compose(&query).unwrap().freeze();

    let response = ObliviousDoHMessagePlaintext::new(b"The IP is 1.1.1.1", 0);
    let response_bytes = compose(&response).unwrap().freeze();

    let (query_enc, cli_secret) = encrypt_query(&query, key_pair.public(), &mut rng).unwrap();
    let query_enc_bytes = compose(&query_enc).unwrap().freeze();

    let (query_dec, srv_secret) = decrypt_query(&query_enc, &key_pair).unwrap();
    //let query_dec_bytes = compose(&query_dec).unwrap().freeze();

    let nonce = ResponseNonce::default();
    let response_enc = encrypt_response(&query_dec, &response, srv_secret, nonce).unwrap();
    let response_enc_bytes = compose(&response_enc).unwrap().freeze();

    c.bench_function("step_encrypt_query", |b| {
        b.iter(|| {
            black_box({
                let query = parse(&mut query_bytes.clone()).unwrap();
                encrypt_query(&query, key_pair.public(), &mut rng).unwrap()
            })
        })
    });

    c.bench_function("step_decrypt_query", |b| {
        b.iter(|| {
            black_box({
                let query_enc = parse(&mut query_enc_bytes.clone()).unwrap();
                decrypt_query(&query_enc, &key_pair).unwrap()
            })
        })
    });

    c.bench_function("step_encrypt_response", |b| {
        b.iter(|| {
            black_box({
                let nonce = ResponseNonce::default();
                let response = parse(&mut response_bytes.clone()).unwrap();
                encrypt_response(&response, &response, srv_secret, nonce).unwrap()
            })
        })
    });

    c.bench_function("step_decrypt_response", |b| {
        b.iter(|| {
            black_box({
                let response_enc = parse(&mut response_enc_bytes.clone()).unwrap();
                decrypt_response(&query, &response_enc, cli_secret).unwrap()
            })
        })
    });
}

criterion_group!(benches, bench_steps,);
criterion_main!(benches);

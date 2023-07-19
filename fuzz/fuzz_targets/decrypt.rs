#![no_main]

use libfuzzer_sys::fuzz_target;
use odoh_rs::{decrypt_query, Deserialize, ObliviousDoHKeyPair, ObliviousDoHMessage};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::hint::black_box;

fuzz_target!(|data: Vec<u8>| {
    let mut rng = StdRng::from_seed([0; 32]);
    let key_pair = ObliviousDoHKeyPair::new(&mut rng);

    let slice = &mut data.as_slice();
    let Ok(msg) = ObliviousDoHMessage::deserialize(slice) else {
        return;
    };

    let _ = black_box(decrypt_query(&msg, &key_pair));
});

mod util;

use rcgen::{Certificate, KeyPair, RcgenError};
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

use wasm_bindgen_test::*;

wasm_bindgen_test_configure!(run_in_browser);

fn generate_hash<T: Hash>(subject: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    subject.hash(&mut hasher);
    hasher.finish()
}

#[wasm_bindgen_test]
#[test]
fn test_key_params_mismatch() {
    let available_key_params = [
        #[cfg(not(target_family = "wasm"))]
        &rcgen::PKCS_RSA_SHA256,
        #[cfg(not(target_family = "wasm"))]
        &rcgen::PKCS_ECDSA_P256_SHA256,
        #[cfg(not(target_family = "wasm"))]
        &rcgen::PKCS_ECDSA_P384_SHA384,
        &rcgen::PKCS_ED25519,
    ];
    for (i, kalg_1) in available_key_params.iter().enumerate() {
        for (j, kalg_2) in available_key_params.iter().enumerate() {
            if i == j {
                assert_eq!(*kalg_1, *kalg_2);
                assert_eq!(generate_hash(*kalg_1), generate_hash(*kalg_2));
                continue;
            }

            assert_ne!(*kalg_1, *kalg_2);
            assert_ne!(generate_hash(*kalg_1), generate_hash(*kalg_2));

            let mut wrong_params = util::default_params();
            if i != 0 {
                wrong_params.key_pair = Some(KeyPair::generate(kalg_1).unwrap());
            } else {
                let kp = KeyPair::from_pem(util::RSA_TEST_KEY_PAIR_PEM).unwrap();
                wrong_params.key_pair = Some(kp);
            }
            wrong_params.alg = *kalg_2;

            assert_eq!(
                Certificate::from_params(wrong_params).err(),
                Some(RcgenError::CertificateKeyPairMismatch),
                "i: {} j: {}",
                i,
                j
            );
        }
    }
}

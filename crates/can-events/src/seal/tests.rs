//! A seal that accepts a forgery is worse than no seal, so every test
//! here changes one thing about a valid seal and expects a refusal.

use super::*;

const KEY: [u8; 32] = [7u8; 32];
const HEAD: [u8; 32] = [0xab; 32];

fn head_hex() -> String {
    hex(&HEAD)
}

fn signed() -> (SealKey, String) {
    let key = SealKey::from_bytes(KEY);
    let signature = key.sign("r-1", "cli", 12, &HEAD);

    (key, signature)
}

#[test]
fn a_seal_verifies_against_the_stream_it_closed() {
    let (key, signature) = signed();

    verify(
        SEAL_ALGORITHM,
        &key.public_key_hex(),
        &signature,
        "r-1",
        "cli",
        12,
        &head_hex(),
    )
    .expect("the seal must verify against what was signed");
}

#[test]
fn a_seal_does_not_transfer_to_another_stream() {
    let (key, signature) = signed();

    for (run_id, stream, events) in [("r-2", "cli", 12), ("r-1", "proxy", 12), ("r-1", "cli", 11)] {
        let result = verify(
            SEAL_ALGORITHM,
            &key.public_key_hex(),
            &signature,
            run_id,
            stream,
            events,
            &head_hex(),
        );

        assert!(
            matches!(result, Err(SealError::BadSignature)),
            "a seal for one stream must not verify for {run_id}/{stream}/{events}"
        );
    }
}

#[test]
fn a_rewritten_chain_head_is_refused() {
    let (key, signature) = signed();
    let other = hex(&[0xcd; 32]);

    assert!(matches!(
        verify(
            SEAL_ALGORITHM,
            &key.public_key_hex(),
            &signature,
            "r-1",
            "cli",
            12,
            &other
        ),
        Err(SealError::BadSignature)
    ));
}

#[test]
fn another_key_does_not_verify() {
    let (_key, signature) = signed();
    let impostor = SealKey::from_bytes([9u8; 32]);

    assert!(matches!(
        verify(
            SEAL_ALGORITHM,
            &impostor.public_key_hex(),
            &signature,
            "r-1",
            "cli",
            12,
            &head_hex()
        ),
        Err(SealError::BadSignature)
    ));
}

#[test]
fn an_unknown_algorithm_is_refused_rather_than_guessed() {
    let (key, signature) = signed();

    assert!(matches!(
        verify(
            "hmac-sha256",
            &key.public_key_hex(),
            &signature,
            "r-1",
            "cli",
            12,
            &head_hex()
        ),
        Err(SealError::Algorithm(_))
    ));
}

#[test]
fn malformed_fields_are_named() {
    let (key, signature) = signed();

    let bad_signature = verify(
        SEAL_ALGORITHM,
        &key.public_key_hex(),
        "zz",
        "r-1",
        "cli",
        12,
        &head_hex(),
    );
    assert!(matches!(
        bad_signature,
        Err(SealError::Malformed {
            field: "signature",
            ..
        })
    ));

    let bad_key = verify(
        SEAL_ALGORITHM,
        "abcd",
        &signature,
        "r-1",
        "cli",
        12,
        &head_hex(),
    );
    assert!(matches!(
        bad_key,
        Err(SealError::Malformed {
            field: "public_key",
            ..
        })
    ));
}

#[test]
fn a_key_file_may_be_raw_or_hex() {
    let dir = tempfile::tempdir().expect("tempdir");

    let raw = dir.path().join("raw.key");
    std::fs::write(&raw, KEY).expect("write raw");

    let as_hex = dir.path().join("hex.key");
    std::fs::write(&as_hex, format!("{}\n", hex(&KEY))).expect("write hex");

    let from_raw = SealKey::from_file(&raw).expect("raw key");
    let from_hex = SealKey::from_file(&as_hex).expect("hex key");

    assert_eq!(from_raw.public_key_hex(), from_hex.public_key_hex());
    assert_eq!(
        from_raw.public_key_hex(),
        SealKey::from_bytes(KEY).public_key_hex()
    );
}

#[test]
fn a_key_file_of_the_wrong_size_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("short.key");
    std::fs::write(&path, b"too short").expect("write");

    assert!(matches!(
        SealKey::from_file(&path),
        Err(SealError::KeyLength { .. })
    ));
}

#[test]
fn debug_never_prints_key_material() {
    let key = SealKey::from_bytes(KEY);
    let printed = format!("{key:?}");

    assert!(printed.contains(&key.public_key_hex()));
    assert!(
        !printed.contains(&hex(&KEY)),
        "a signing key must not reach a log line"
    );
}

#[test]
fn a_multi_byte_character_is_malformed_not_a_panic() {
    // "é" is two bytes: each of these has an even byte length, and in
    // "aaé" and "0é0" a two-byte step lands inside the character.
    for candidate in ["aaé", "0é0", "éé"] {
        assert_eq!(candidate.len() % 2, 0, "precondition: {candidate:?}");

        assert!(
            matches!(
                unhex(candidate, "signature"),
                Err(SealError::Malformed {
                    field: "signature",
                    ..
                })
            ),
            "{candidate:?} must be refused as malformed"
        );
    }
}

#[test]
fn a_multi_byte_character_in_a_seal_field_is_refused() {
    let (key, _signature) = signed();
    let signature = format!("{}é", "a".repeat(126));

    assert!(matches!(
        verify(
            SEAL_ALGORITHM,
            &key.public_key_hex(),
            &signature,
            "r-1",
            "cli",
            12,
            &head_hex()
        ),
        Err(SealError::Malformed {
            field: "signature",
            ..
        })
    ));
}

#[test]
fn an_odd_number_of_hex_characters_is_malformed() {
    assert!(matches!(
        unhex("abc", "public_key"),
        Err(SealError::Malformed {
            field: "public_key",
            ..
        })
    ));
}

#[test]
fn non_hex_ascii_is_malformed() {
    for candidate in ["zz", "0g", "+1", "-1", " 1", "0x"] {
        assert!(
            matches!(unhex(candidate, "key"), Err(SealError::Malformed { .. })),
            "{candidate:?} must be refused"
        );
    }
}

#[test]
fn hex_decodes_both_cases() {
    assert_eq!(
        unhex("00ffAb10", "key").expect("valid hex"),
        vec![0x00, 0xff, 0xab, 0x10]
    );
    assert_eq!(unhex("", "key").expect("empty"), Vec::<u8>::new());
}

#[test]
fn a_key_file_with_a_multi_byte_character_is_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("utf8.key");
    std::fs::write(&path, format!("{}é", "a".repeat(62))).expect("write");

    assert!(matches!(
        SealKey::from_file(&path),
        Err(SealError::KeyLength { .. })
    ));
}

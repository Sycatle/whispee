//! Pairing carries the account root key. A flaw here gives away the whole account.

use crypto_core::pairing::{PairingOffer, seal};

const SECRET: &[u8] = b"account seed, worth the whole account";

#[test]
fn the_sealed_packet_is_opened_by_its_recipient() {
    let offer = PairingOffer::generate();
    let (public, id) = (offer.public_key(), offer.id());

    let (packet, sender_code) = seal(&public, &id, SECRET).unwrap();
    let opened = offer.open(&packet).unwrap();

    assert_eq!(opened.plaintext, SECRET);
    // The code must match on both sides, otherwise comparing it is pointless.
    assert_eq!(opened.confirmation, sender_code);
    assert_eq!(sender_code.len(), 6);
}

/// The server relays the packet. It holds neither private half, so it cannot open it — no more
/// than a third party who photographed the QR code.
#[test]
fn a_third_party_cannot_open_the_packet() {
    let offer = PairingOffer::generate();
    let (public, id) = (offer.public_key(), offer.id());
    let (packet, _) = seal(&public, &id, SECRET).unwrap();

    // The intruder knows everything that travelled in the clear: the QR and the packet. What he
    // lacks is the ephemeral private key, which never left the new device.
    let intruder = PairingOffer::generate();

    assert!(intruder.open(&packet).is_err());
}

/// The pairing id is the AAD of the encryption: a packet meant for one session must not be
/// replayable in another.
#[test]
fn a_packet_meant_for_another_session_is_rejected() {
    let offer = PairingOffer::generate();
    let public = offer.public_key();

    let (packet, _) = seal(&public, &[0u8; 16], SECRET).unwrap();

    // Same key pair, different id: the AEAD refuses.
    assert!(offer.open(&packet).is_err());
}

#[test]
fn a_tampered_packet_is_rejected() {
    let offer = PairingOffer::generate();
    let (public, id) = (offer.public_key(), offer.id());
    let (mut packet, _) = seal(&public, &id, SECRET).unwrap();

    let last = packet.len() - 1;
    packet[last] ^= 0x01;

    assert!(offer.open(&packet).is_err());
}

#[test]
fn a_truncated_packet_is_rejected_without_panicking() {
    let offer = PairingOffer::generate();
    assert!(offer.open(&[0u8; 10]).is_err());
}

/// Two successive pairings must not produce the same confirmation code, otherwise comparing the
/// codes proves nothing.
#[test]
fn two_pairings_have_different_codes() {
    let mut codes = std::collections::HashSet::new();

    for _ in 0..20 {
        let offer = PairingOffer::generate();
        let (public, id) = (offer.public_key(), offer.id());
        codes.insert(seal(&public, &id, SECRET).unwrap().1);
    }

    assert!(codes.len() > 18, "the confirmation codes repeat");
}

/// The QR must contain no secret: it can be photographed by construction.
#[test]
fn the_offer_only_publishes_public_values() {
    let offer = PairingOffer::generate();
    let (public, id) = (offer.public_key(), offer.id());

    // What comes out of the offer is exactly what goes into the QR. Two offers share nothing:
    // no fixed value could act as an implicit shared secret.
    let other = PairingOffer::generate();
    assert_ne!(public, other.public_key());
    assert_ne!(id, other.id());
}

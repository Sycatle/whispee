//! Architecture invariants, enforced by CI.

/// `crypto-core` is the only production path. `ratchet-lab` is unaudited teaching code, written
/// to understand the protocol, not to protect anyone.
///
/// This test fails if someone adds the dependency — probably to reuse a function "just for a
/// test" or "in the meantime". That is exactly how home-made crypto ends up in production.
#[test]
fn crypto_core_never_depends_on_ratchet_lab() {
    let manifest = include_str!("../Cargo.toml");

    let offending: Vec<_> = manifest
        .lines()
        .map(str::trim)
        // The manifest mentions `ratchet-lab` in the comment that states the invariant.
        .filter(|line| !line.starts_with('#'))
        .filter(|line| line.contains("ratchet-lab") || line.contains("ratchet_lab"))
        .collect();

    assert!(
        offending.is_empty(),
        "crypto-core must never depend on ratchet-lab; offending lines: {offending:?}"
    );
}

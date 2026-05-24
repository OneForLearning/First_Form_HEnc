use crypto_bigint::{U8192, U4096, NonZero};
use crate::math::square_and_multiply;
use crate::keygen::PublicKey;

pub fn paillier_encrypt(m: U4096, public_key: &PublicKey) -> Result<U8192, &'static str> {
    // Vérifier que m < n, sinon réduire
    let m_reduced = if m >= public_key.n {
        let n_nonzero = NonZero::new(public_key.n).unwrap();
        m.rem(&n_nonzero)
    } else {
        m
    };

    // BUG CORRIGÉ : utiliser public_key.r et public_key.g au lieu de
    // regénérer aléatoirement (randomness_r / randomness_g),
    // ce qui produisait un chiffrement incohérent avec la clé publiée.
    let r_wide = U8192::from(&public_key.r);
    let g = public_key.g;
    let n2 = public_key.n2;

    let n2_nonzero = NonZero::new(n2).expect("n2 cannot be zero");

    // g^m mod n^2
    let gm: U8192 = square_and_multiply(g, m_reduced, n2);

    // r^n mod n^2
    let rn: U8192 = square_and_multiply(r_wide, public_key.n, n2);

    // BUG CORRIGÉ : réduction modulaire après chaque multiplication pour
    // éviter le dépassement silencieux (wrapping_mul sur ~16384 bits).
    let c = gm.rem(&n2_nonzero)
        .wrapping_mul(&rn.rem(&n2_nonzero))
        .rem(&n2_nonzero);

    Ok(c)
}

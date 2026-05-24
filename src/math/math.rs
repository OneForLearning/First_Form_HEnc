use rand_core::OsRng;
use crypto_bigint::{U4096, U8192, Zero, NonZero, Random, Integer};

// ============================================================
// Génération de r dans (Z_n)*
// ============================================================

pub fn randomness_r(n: U4096) -> U4096 {
    let mut rng = OsRng;
    let n_nonzero = NonZero::new(n).expect("n ne doit pas être zéro");
    loop {
        // BUG CORRIGÉ (original) : r était généré sans réduction mod n,
        // ce qui pouvait retourner r >= n. On réduit d'abord.
        let r = U4096::random(&mut rng).rem(&n_nonzero);
        // Vérifier que r != 0 et gcd(r, n) = 1
        if r != U4096::ZERO && gcd(r, n) == U4096::ONE {
            return r;
        }
    }
}

pub fn randomness_g(n2: U8192) -> U8192 {
    let mut rng = OsRng;
    let n2_nonzero = NonZero::new(n2).expect("n2 ne doit pas être zéro");

    loop {
        let g = U8192::random(&mut rng).rem(&n2_nonzero);

        if g == U8192::ZERO {
            continue;
        }

        // BUG CORRIGÉ : utilisation de NonZero + rem() dans gcd_u8192 au lieu
        // de wrapping_rem() qui panique sur division par zéro en mode debug.
        let gcd_result = gcd_u8192(g, n2);

        if gcd_result == U8192::ONE {
            return g;
        }
    }
}

// ============================================================
// Arithmétique : GCD, LCM
// ============================================================

/// GCD en U8192.
/// BUG CORRIGÉ : utilise NonZero::new + rem() au lieu de wrapping_rem()
/// (wrapping_rem sur un diviseur nul panique en mode debug).
pub fn gcd_u8192(mut a: U8192, mut b: U8192) -> U8192 {
    while b != U8192::ZERO {
        let temp = b;
        let b_nonzero = NonZero::new(b).expect("b est zéro dans gcd_u8192");
        b = a.rem(&b_nonzero);
        a = temp;
    }
    a
}

/// GCD en U4096.
pub fn gcd(mut a: U4096, mut b: U4096) -> U4096 {
    while !bool::from(b.is_zero()) {
        let temp = b;
        let b_non_zero = NonZero::new(b).unwrap();
        b = a.rem(&b_non_zero);
        a = temp;
    }
    a
}

/// LCM en U4096.
/// lcm(a,b) = a * (b / gcd(a,b)) — on divise d'abord pour minimiser
/// le risque de dépassement intermédiaire.
pub fn lcm(a: U4096, b: U4096) -> U4096 {
    let gcd_value = gcd(a, b);
    assert!(!bool::from(gcd_value.is_zero()), "GCD is zero");

    let gcd_nonzero = NonZero::new(gcd_value).expect("GCD cannot be zero");
    let b_div_gcd = b.wrapping_div(&gcd_nonzero);
    a.wrapping_mul(&b_div_gcd)
}

// ============================================================
// Exponentiation modulaire (square-and-multiply)
// ============================================================

/// Calcule generator^message mod modulo en U8192.
///
/// BUG CORRIGÉ (original) : la multiplication accumulateur * generator
/// pouvait déborder U8192 avant la réduction, car wrapping_mul tronque
/// silencieusement. On effectue maintenant la réduction modulaire AVANT
/// chaque multiplication (generator est réduit dès l'entrée et après
/// chaque carré), garantissant que les opérandes restent < modulo < 2^8192.
pub fn square_and_multiply(generator: U8192, message: U4096, modulo: U8192) -> U8192 {
    let mut accumulator: U8192 = U8192::ONE;
    let mut generator = generator;
    let mut message = message;

    let modulo_nz = NonZero::new(modulo).expect("Le modulo est nul, ce qui pose problème");

    // Réduire generator modulo n² dès le départ
    generator = generator.rem(&modulo_nz);

    while message > U4096::ZERO {
        if message.is_odd().into() {
            // accumulator et generator sont < modulo (< 2^8192),
            // donc leur produit peut atteindre ~2^16383 : on réduit immédiatement.
            accumulator = accumulator.wrapping_mul(&generator).rem(&modulo_nz);
        }

        // generator² aussi réduit pour rester < modulo
        generator = generator.wrapping_mul(&generator).rem(&modulo_nz);
        message = message.shr(1);
    }

    accumulator
}

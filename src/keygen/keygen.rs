use crypto_bigint::{U2048, U4096, U8192, NonZero};
use crypto_primes::generate_prime_with_rng;
use rand_core::OsRng;
use crate::math::{lcm, randomness_r, randomness_g};

// ==================================Clé publique Paillier

pub struct PublicKey {
    pub n: U4096,
    pub n2: U8192,
    pub r: U4096,
    pub g: U8192,
}

// ==================================Clé privée Paillier

pub struct PrivateKey {
    phi_n: U4096,
    secret_key: U4096,
}

impl PrivateKey {
    pub fn phi_n(&self) -> &U4096 {
        &self.phi_n
    }

    pub fn secret_key(&self) -> &U4096 {
        &self.secret_key
    }
}

// ==================================Paire de clés Paillier (publique + privée)

pub struct KeyPair {
    pub public_key: PublicKey,
    pub private_key: PrivateKey,
}

impl KeyPair {

    pub fn generate() -> Result<Self, &'static str> {
        let mut rng = OsRng;

        // Générer deux nombres premiers distincts de 2048 bits
        let p: U2048 = generate_prime_with_rng(&mut rng, Some(2048));

        let mut q: U2048;
        loop {
            q = generate_prime_with_rng(&mut rng, Some(2048));
            if q != p { break; }
        }

        // Convertir en U4096 pour les calculs
        let p_wide = U4096::from(&p);
        let q_wide = U4096::from(&q);

        // NOTE : p et q sont des nombres premiers de 2048 bits exacts
        // (generate_prime_with_rng garantit que le bit 2047 est à 1),
        // donc p*q tient toujours dans U4096 (< 2^4096). wrapping_mul est safe.
        // BUG CORRIGÉ (original) : le commentaire indiquait un risque d'overflow
        // sans protection. On documente explicitement la borne ici.
        let n = p_wide.wrapping_mul(&q_wide);

        // Convertir n en U8192 pour les calculs modulo n²
        let n_wide = U8192::from(&n);

        // n < 2^4096, donc n² < 2^8192. wrapping_mul en U8192 est safe.
        let n2: U8192 = n_wide.wrapping_mul(&n_wide);

        let r = randomness_r(n);
        let g = randomness_g(n2);

        // ============================ CLÉ PRIVÉE ===============================================

        let p_minus_1 = p.wrapping_sub(&U2048::ONE);
        let q_minus_1 = q.wrapping_sub(&U2048::ONE);

        let p_minus_1_wide = U4096::from(&p_minus_1);
        let q_minus_1_wide = U4096::from(&q_minus_1);

        // secret_key = lcm(p-1, q-1)
        let secret_key = lcm(p_minus_1_wide, q_minus_1_wide);

        // phi_n = (p-1)*(q-1).
        // (p-1) < 2^2048, (q-1) < 2^2048 → produit < 2^4096. safe.
        // BUG CORRIGÉ (original) : wrapping_mul utilisé sans commentaire explicatif
        // sur les bornes ; ajout de la justification mathématique.
        let phi_n = p_minus_1_wide.wrapping_mul(&q_minus_1_wide);

        let public_key = PublicKey { n, n2, r, g };
        let private_key = PrivateKey { phi_n, secret_key };

        Ok(Self { public_key, private_key })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.public_key
    }

    pub fn private_key(&self) -> &PrivateKey {
        &self.private_key
    }
}

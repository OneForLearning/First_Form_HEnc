# Homomorphic Encryption based on Paillier Encryption Scheme in Rust

> A from-scratch implementation of the Paillier cryptosystem in Rust, featuring arbitrary-precision integers, constant-time execution, and a modular library-oriented design.

---

## Table of Contents

- [Context and Goals](#context-and-goals)
- [The Paillier Cryptosystem](#the-paillier-cryptosystem)
- [Project Architecture](#project-architecture)
- [Technical Details](#technical-details)
- [Usage](#usage)
- [Dependencies](#dependencies)
- [Future Work](#future-work)

---

## Context and Goals

This project is a technical and pedagogical implementation of the **Paillier cryptosystem**, an asymmetric encryption scheme with **additive homomorphic** properties. It was developed in Rust with the following goals:

- Gain a deep understanding of the mathematical construction behind the Paillier scheme.
- Master large integer arithmetic (2048, 4096, 8192 bits) using the `crypto-bigint` library.
- Apply Rust cryptography best practices: no heap allocations, constant-time operations, explicit overflow handling.
- Produce a modular, extensible codebase ready for decryption and homomorphic operations.

---

## The Paillier Cryptosystem

The Paillier scheme (Pascal Paillier, 1999) is a probabilistic asymmetric cryptosystem based on the **Decisional Composite Residuosity Assumption (DCRA)**. Its central property is **additive homomorphism**: additions can be performed directly on ciphertexts, without ever decrypting them.

### Homomorphic Property

```
Enc(m₁) · Enc(m₂) mod n²  =  Enc(m₁ + m₂)
```

This allows, for example, aggregating encrypted votes or computing a sum over private data without revealing it.

### Key Generation

1. Choose two large distinct primes **p** and **q** (2048 bits each).
2. Compute **n = p · q** (4096 bits) and **n² = n · n** (8192 bits).
3. Choose **g** at random in ℤ\*_{n²} such that gcd(g, n²) = 1.
4. Choose **r** at random in ℤ\*_n such that gcd(r, n) = 1.
5. The **secret key** is λ = lcm(p−1, q−1).
6. φ(n) = (p−1)(q−1) is also stored.

### Encryption

For a message **m** such that 0 ≤ m < n:

```
c = g^m · r^n  mod n²
```

The probabilistic nature comes from **r**: two encryptions of the same message produce different ciphertexts.

### Decryption *(implemented, not wired into the demo)*

The auxiliary function **L(u) = (u − 1) / n** is used to recover m:

```
m = L(c^λ mod n²) · μ  mod n
```

where **μ = L(g^λ mod n²)⁻¹ mod n**.

---

## Project Architecture

```
PaillierCT/
├── Cargo.toml
├── src/
│   ├── lib.rs                  # Library entry point
│   ├── main.rs                 # Demo: key generation + encryption
│   ├── keygen/
│   │   ├── mod.rs
│   │   └── keygen.rs           # Key pair generation (KeyPair, PublicKey, PrivateKey)
│   ├── encrypt/
│   │   ├── mod.rs
│   │   └── encrypt.rs          # Encryption function: paillier_encrypt()
│   └── math/
│       ├── mod.rs
│       ├── math.rs             # Primitives: GCD, LCM, square_and_multiply, randomness
│       └── math_g.rs           # Reserved: g verification via L(g^λ) (future work)
```

### Core Modules

**`keygen`** — Key Generation  
Generates p and q (2048 bits) via `crypto-primes`, computes n, n², r, g, λ = lcm(p−1, q−1) and φ(n). Exposes the `KeyPair`, `PublicKey`, and `PrivateKey` structs.

**`encrypt`** — Encryption  
Implements `paillier_encrypt(m, &public_key) -> Result<U8192>`. Uses the g and r parameters from the public key (not freshly generated random values — a critical bug that was fixed).

**`math`** — Cryptographic Primitives  
Contains:
- `gcd(a, b)` and `gcd_u8192(a, b)` — Euclidean algorithm using `NonZero` to prevent panics.
- `lcm(a, b)` — computed as `a · (b / gcd)` to stay within U4096 bounds.
- `square_and_multiply(g, m, n)` — bitwise modular exponentiation with reduction at every step.
- `randomness_r(n)` and `randomness_g(n²)` — rejection sampling in ℤ\*_n and ℤ\*_{n²}.

---

## Technical Details

### Large Integer Arithmetic

The project exclusively uses **`crypto-bigint`** (no heap allocations):

| Variable     | Type    | Size       |
|--------------|---------|------------|
| p, q         | U2048   | 2048 bits  |
| n            | U4096   | 4096 bits  |
| n², g, c     | U8192   | 8192 bits  |
| r, φ(n), λ   | U4096   | 4096 bits  |

### Security and Robustness

- **Constant-time**: all operations use `crypto-bigint` primitives, designed to resist side-channel attacks (timing attacks).
- **Arithmetic overflow**: critical multiplications (n = p·q, n² = n·n, φ(n)) are documented with mathematical bounds justification; multiplications inside `square_and_multiply` are reduced modulo n² at every step.
- **Panic-free GCD**: `NonZero::new()` is used systematically before any `rem()` call, preventing division-by-zero in debug mode.
- **Rejection sampling**: r and g are generated in a rejection loop until gcd = 1 is satisfied, guaranteeing membership in the required multiplicative groups.

### Bugs Identified and Fixed

| # | File | Description |
|---|------|-------------|
| 1 | `encrypt.rs` | g and r were randomly regenerated instead of using the public key → ciphertext inconsistent with the key |
| 2 | `encrypt.rs` | Multiplication `gm · rn` without intermediate modular reduction → silent overflow |
| 3 | `math.rs` | `wrapping_rem` in `gcd_u8192` → potential panic on zero divisor |
| 4 | `math.rs` | r generated without reduction mod n → r could be ≥ n |
| 5 | `math_g.rs` | Dead file with duplicate imports and APIs incompatible with crypto-bigint 0.5 |

---

## Usage

### Prerequisites

- Rust 1.65+ (edition 2021)
- Cargo

### Run the Demo

```bash
git clone <repo>
cd PaillierCT
cargo run
```

The demo outputs:

```
===== Paillier Key Generation =====

Generating keys...
Keys generated successfully!

--- PUBLIC KEY ---
n  = <4096 bits>
n² = <8192 bits>
g  = <8192 bits>
r  = <4096 bits>

--- PRIVATE KEY ---
phi(n)     = <4096 bits>
secret_key = <4096 bits>

===== Message Encryption =====

Original message (decimal): <random integer>
Verification: message < n? true

✓ ENCRYPTION SUCCESSFUL!
Ciphertext: <8192 bits in hexadecimal>
Ciphertext size: 8192 bits
```

### Use as a Library

```rust
use paillier_r::{KeyPair, paillier_encrypt};
use crypto_bigint::{U4096, Random};
use rand_core::OsRng;

fn main() {
    // Generate key pair
    let keypair = KeyPair::generate().expect("Key generation failed");

    // Encrypt a message m < n
    let mut rng = OsRng;
    let message = U4096::random(&mut rng);
    let ciphertext = paillier_encrypt(message, &keypair.public_key)
        .expect("Encryption failed");

    println!("Ciphertext: {:X}", ciphertext);
}
```

---

## Dependencies

| Crate | Version | Role |
|-------|---------|------|
| `crypto-bigint` | 0.5 | Fixed-precision integers, constant-time, no heap allocations |
| `crypto-primes` | 0.5 | Cryptographic prime number generation |
| `rand_core` | 0.6 | RNG interface (`OsRng`) |
| `rand` | 0.8 | Random generation utilities |
| `zeroize` | 1.8 | Secure in-memory erasure of sensitive data *(planned)* |

---

## Future Work

The project is structured to accommodate the following extensions, already outlined in `lib.rs`:

- **Decryption** (`decrypt`) — L function and μ computation; `paillier_decrypt` module drafted in `math_g.rs`.
- **Homomorphic addition** (`addHomomorphic`) — multiplication of ciphertexts modulo n².
- **Scalar multiplication** (`mulByPlain`) — exponentiation of a ciphertext by a plaintext constant.
- **g verification** — validate that L(g^λ mod n²) is invertible mod n during key generation.
- **Zeroize on private keys** — automatic memory erasure of p, q, φ(n), λ via the `zeroize` crate.

---

## References

- Paillier, P. (1999). *Public-Key Cryptosystems Based on Composite Degree Residuosity Classes*. EUROCRYPT 1999.
- [crypto-bigint documentation](https://docs.rs/crypto-bigint)
- [crypto-primes documentation](https://docs.rs/crypto-primes)

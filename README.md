# PaillierCT — Implémentation du chiffrement de Paillier en Rust

> Implémentation from scratch du cryptosystème de Paillier en Rust, avec des entiers à précision arbitraire, un temps d'exécution constant et une conception modulaire orientée bibliothèque.

---

## Table des matières

- [Contexte et objectifs](#contexte-et-objectifs)
- [Le cryptosystème de Paillier](#le-cryptosystème-de-paillier)
- [Architecture du projet](#architecture-du-projet)
- [Détails techniques](#détails-techniques)
- [Utilisation](#utilisation)
- [Dépendances](#dépendances)
- [Travaux futurs](#travaux-futurs)

---

## Contexte et objectifs

Ce projet est une implémentation pédagogique et technique du **cryptosystème de Paillier**, un schéma de chiffrement asymétrique à **chiffrement homomorphique additif**. Il a été développé en Rust dans le but de :

- Comprendre en profondeur la construction mathématique du schéma de Paillier.
- Maîtriser la manipulation d'entiers de grande taille (2048, 4096, 8192 bits) avec la bibliothèque `crypto-bigint`.
- Appliquer les bonnes pratiques de cryptographie en Rust : absence d'allocations dynamiques, temps constant, gestion explicite des débordements arithmétiques.
- Produire une base de code modulaire, extensible vers le déchiffrement et les opérations homomorphiques.

---

## Le cryptosystème de Paillier

Le schéma de Paillier (Pascal Paillier, 1999) est un cryptosystème asymétrique probabiliste fondé sur le **problème de la résidu quadratique composite (DCRA)**. Sa propriété centrale est l'**homomorphisme additif** : il est possible d'effectuer des additions sur des messages chiffrés sans jamais déchiffrer.

### Propriété homomorphique

```
Enc(m₁) · Enc(m₂) mod n²  =  Enc(m₁ + m₂)
```

Cela permet, par exemple, d'agréger des votes chiffrés ou de calculer une somme sur des données privées sans les révéler.

### Génération de clés

1. Choisir deux grands nombres premiers distincts **p** et **q** (2048 bits chacun).
2. Calculer **n = p · q** (4096 bits) et **n² = n · n** (8192 bits).
3. Choisir **g** aléatoire dans ℤ\*_{n²} tel que gcd(g, n²) = 1.
4. Choisir **r** aléatoire dans ℤ\*_n tel que gcd(r, n) = 1.
5. La **clé secrète** est λ = lcm(p−1, q−1).
6. φ(n) = (p−1)(q−1) est également conservé.

### Chiffrement

Pour un message **m** tel que 0 ≤ m < n :

```
c = g^m · r^n  mod n²
```

Le caractère probabiliste vient de **r** : deux chiffrements du même message donnent des chiffrés différents.

### Déchiffrement *(implémenté, non intégré dans la démo)*

La fonction auxiliaire **L(u) = (u − 1) / n** permet de retrouver m :

```
m = L(c^λ mod n²) · μ  mod n
```

où **μ = L(g^λ mod n²)⁻¹ mod n**.

---

## Architecture du projet

```
PaillierCT/
├── Cargo.toml
├── src/
│   ├── lib.rs                  # Point d'entrée de la bibliothèque
│   ├── main.rs                 # Démonstration : génération de clés + chiffrement
│   ├── keygen/
│   │   ├── mod.rs
│   │   └── keygen.rs           # Génération de la paire de clés (KeyPair, PublicKey, PrivateKey)
│   ├── encrypt/
│   │   ├── mod.rs
│   │   └── encrypt.rs          # Fonction de chiffrement : paillier_encrypt()
│   └── math/
│       ├── mod.rs
│       ├── math.rs             # Primitives : GCD, LCM, square_and_multiply, randomness
│       └── math_g.rs           # Réservé : vérification de g via L(g^λ) (travaux futurs)
```

### Modules principaux

**`keygen`** — Génération de clés  
Génère p et q (2048 bits) via `crypto-primes`, calcule n, n², r, g, λ = lcm(p−1, q−1) et φ(n). Expose les structs `KeyPair`, `PublicKey` et `PrivateKey`.

**`encrypt`** — Chiffrement  
Implémente `paillier_encrypt(m, &public_key) -> Result<U8192>`. Utilise les paramètres g et r de la clé publique (et non de nouvelles valeurs aléatoires — point critique corrigé).

**`math`** — Primitives cryptographiques  
Contient :
- `gcd(a, b)` et `gcd_u8192(a, b)` — algorithme d'Euclide avec `NonZero` pour éviter les panics.
- `lcm(a, b)` — calculé via `a · (b / gcd)` pour rester dans les bornes de U4096.
- `square_and_multiply(g, m, n)` — exponentiation modulaire bit à bit avec réduction à chaque étape.
- `randomness_r(n)` et `randomness_g(n²)` — génération par rejet dans ℤ\*_n et ℤ\*_{n²}.

---

## Détails techniques

### Gestion des grands entiers

Le projet utilise exclusivement **`crypto-bigint`** (sans allocations heap) :

| Variable | Type    | Taille     |
|----------|---------|------------|
| p, q     | U2048   | 2048 bits  |
| n        | U4096   | 4096 bits  |
| n², g, c | U8192   | 8192 bits  |
| r, φ(n), λ | U4096 | 4096 bits  |

### Sécurité et robustesse

- **Temps constant** : toutes les opérations utilisent les primitives de `crypto-bigint`, conçues pour résister aux attaques par canal auxiliaire (timing attacks).
- **Débordements arithmétiques** : les multiplications critiques (n = p·q, n² = n·n, φ(n)) sont documentées avec justification mathématique des bornes ; la multiplication dans `square_and_multiply` est réduite modulo n² à chaque étape.
- **GCD sans panic** : `NonZero::new()` est utilisé systématiquement avant toute opération `rem()`, évitant les divisions par zéro en mode debug.
- **Génération par rejet** : r et g sont générés par boucle de rejet jusqu'à satisfaire gcd = 1, garantissant qu'ils appartiennent bien aux groupes multiplicatifs requis.

### Bugs identifiés et corrigés

| # | Fichier | Description |
|---|---------|-------------|
| 1 | `encrypt.rs` | g et r recalculés aléatoirement au lieu d'utiliser la clé publique → chiffrement incohérent avec la clé |
| 2 | `encrypt.rs` | Multiplication `gm · rn` sans réduction modulaire intermédiaire → dépassement silencieux |
| 3 | `math.rs` | `wrapping_rem` dans `gcd_u8192` → panic possible sur diviseur nul |
| 4 | `math.rs` | r généré sans réduction mod n → r pouvait être ≥ n |
| 5 | `math_g.rs` | Fichier mort avec imports en double et APIs incompatibles avec crypto-bigint 0.5 |

---

## Utilisation

### Prérequis

- Rust 1.65+ (edition 2021)
- Cargo

### Lancer la démonstration

```bash
git clone <repo>
cd PaillierCT
cargo run
```

La démonstration affiche :

```
===== Génération de clés Paillier =====

Génération des clés en cours...
Clés générées avec succès !

--- CLÉ PUBLIQUE ---
n  = <4096 bits>
n² = <8192 bits>
g  = <8192 bits>
r  = <4096 bits>

--- CLÉ PRIVÉE ---
phi(n)     = <4096 bits>
secret_key = <4096 bits>

===== Chiffrement d'un message =====

Message original (en décimal) : <entier aléatoire>
Vérification : message < n ? true

✓ CHIFFREMENT RÉUSSI !
Le message chiffré est : <8192 bits en hexadécimal>
Taille du chiffré : 8192 bits
```

### Utiliser la bibliothèque

```rust
use paillier_r::{KeyPair, paillier_encrypt};
use crypto_bigint::{U4096, Random};
use rand_core::OsRng;

fn main() {
    // Génération de la paire de clés
    let keypair = KeyPair::generate().expect("Échec de la génération de clés");

    // Chiffrement d'un message m < n
    let mut rng = OsRng;
    let message = U4096::random(&mut rng);
    let ciphertext = paillier_encrypt(message, &keypair.public_key)
        .expect("Échec du chiffrement");

    println!("Chiffré : {:X}", ciphertext);
}
```

---

## Dépendances

| Crate | Version | Rôle |
|-------|---------|------|
| `crypto-bigint` | 0.5 | Entiers à précision fixe, temps constant, sans allocations |
| `crypto-primes` | 0.5 | Génération de nombres premiers cryptographiques |
| `rand_core` | 0.6 | Interface RNG (`OsRng`) |
| `rand` | 0.8 | Utilitaires de génération aléatoire |
| `zeroize` | 1.8 | Effacement sécurisé des données sensibles en mémoire *(prévu)* |

---

## Travaux futurs

Le projet est structuré pour accueillir les extensions suivantes, déjà esquissées dans `lib.rs` :

- **Déchiffrement** (`decrypt`) — fonction L et calcul de μ, module `paillier_decrypt` préparé dans `math_g.rs`.
- **Addition homomorphique** (`addHomomorphic`) — multiplication de chiffrés modulo n².
- **Multiplication par un scalaire** (`mulByPlain`) — exponentiation du chiffré par une constante.
- **Vérification de g** — validation que L(g^λ mod n²) est inversible mod n lors de la génération de clés.
- **Zeroize sur les clés privées** — effacement mémoire automatique de p, q, φ(n), λ via la crate `zeroize`.

---

## Références

- Paillier, P. (1999). *Public-Key Cryptosystems Based on Composite Degree Residuosity Classes*. EUROCRYPT 1999.
- [crypto-bigint documentation](https://docs.rs/crypto-bigint)
- [crypto-primes documentation](https://docs.rs/crypto-primes)
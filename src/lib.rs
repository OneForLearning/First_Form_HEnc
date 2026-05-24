pub mod math;
pub mod keygen;
pub mod encrypt;
//pub mod decrypt;
//pub mod addHomomorphic;
//pub mod mulByPlain;

// Exporter les fonctions
pub use encrypt::paillier_encrypt;
pub use keygen::{KeyPair, PublicKey, PrivateKey};

//pub use decrypt::paillier_decrypt;

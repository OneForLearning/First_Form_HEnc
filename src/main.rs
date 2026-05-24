use paillier_r::{KeyPair, PublicKey, PrivateKey, paillier_encrypt};
use crypto_bigint::{U4096, Random};
use rand_core::OsRng;

fn main() {
	
	let mut rng = OsRng;
	
    println!("===== Génération de clés Paillier =====\n");
    
    // Générer la paire de clés
    println!("Génération des clés en cours...");
    let keypair = KeyPair::generate().expect("Key generation failed");
    println!("Clés générées avec succès !\n");
    
    // Afficher la clé publique
	
    println!("--- CLÉ PUBLIQUE ---");
    println!("n = {:X}", keypair.public_key.n);
	println!("=========================");
	println!("n2 = {:X}", keypair.public_key.n2);
	println!("=========================");
	println!("g = {:X}", keypair.public_key.g);
	println!("=========================");
	println!("r = {:X}", keypair.public_key.r);
    
    // Afficher la clé privée
	
    println!("\n--- CLÉ PRIVÉE ---");
    println!("phi(n) = {:X}", keypair.private_key.phi_n());
	//println!("=========================");
    //println!("mu = {:X}", keypair.private_key.mu());
	println!("=========================");
    println!("secret_key = {:X}", keypair.private_key.secret_key());
    
    // Afficher les tailles
	
    println!("\n--- TAILLES (en bits) ---");
    println!("Taille de n: {} bits", keypair.public_key.n.bits());
	println!("Taille de n au carré : {} bits", keypair.public_key.n2.bits());
    println!("Taille de r: {} bits", keypair.public_key.r.bits());
	println!("Taille de g: {} bits", keypair.public_key.g.bits());
    println!("Taille de phi(n): {} bits", keypair.private_key.phi_n().bits());
	println!("Taille de secret_key : {} bits", keypair.private_key.secret_key().bits());
	
	/* println!("p = {:X}", keypair.private_key.get_p().bits());
	println!("p = {:X}", keypair.private_key.get_q().bits()); */
	
    
    // Exemple : distribuer uniquement la clé publique
	
    println!("\n--- DISTRIBUTION ---");
    let pk = keypair.public_key();
    println!("Clé Publiques partageables : n a bits {} ", pk.n.bits());
	
	
	// CHIFFREMENT D'UN MESSAGE
	println!("\n===== Chiffrement d'un message =====\n");
	
	// Définir un message à chiffrer (doit être < n)
	
	// Message simple
	
	let message = U4096::random(&mut rng);

	
	println!("Message original (en décimal) : {}", message);
	//println!("Message original (en hexadécimal) : {:X}", message);
	println!("\nVérification : message < n ? {}", message < keypair.public_key.n);
	
	println!("\nAppel de paillier_encrypt...");
	
	// Chiffrer le message - paillier_encrypt retourne un Result
	let result = paillier_encrypt(message, &keypair.public_key);
	
	println!("Résultat de paillier_encrypt reçu : {:?}", result.is_ok());
	
	match result {
		Ok(c) => {
			println!("\n✓ CHIFFREMENT RÉUSSI !");
			println!("\n--- MESSAGE CHIFFRÉ ---");
			println!("Le message chiffré est : {:X}", c);
			println!("Taille du chiffré : {} bits", c.bits());
		},
		Err(e) => {
			println!("\n✗ ERREUR lors du chiffrement : {}", e);
		}
	}
	
	println!("\nFin du programme.");
}
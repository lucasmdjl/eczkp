# eczkp - A Library for Zero Knowledge Proofs using Elliptic Curves

`eczkp` is a Rust library that implements zero-knowledge proofs (ZKP) using elliptic curve cryptography.
It enables one party (the prover) to prove knowledge of a secret without revealing it, while the other party (the verifier)
can verify the proof without learning the secret.

Currently, `eczkp` supports the following ZKP protocols:
- Schnorr ZKP prtocol

## Features

- **Prover and Verifier**: Provides easy-to-use abstractions for both the prover and verifier roles in a ZKP protocol.
- **Elliptic Curve Support**: Leverages elliptic curve cryptography via the `elliptic_curve` crate, making the protocol secure and efficient.
- **Commitment, Challenge, Answer**: Implements all necessary cryptographic constructs for a standard ZKP.
- **Secure Memory Handling**: Uses the `zeroize` crate to ensure secret data (such as private keys and nonces) is securely wiped from memory after use.
- **Random Nonce and Challenge Generation**: Secure generation of nonces and challenges using cryptographic random number generators.

## Getting Started

### Installation

Add the following to your `Cargo.toml` file:

```toml
[dependencies]
eczkp = "0.1.1"
```

### Example Usage

Below is a simple example showing how to use `eczkp` to perform a zero-knowledge proof.

```rust
use eczkp::schnorr::ec::{SchnorrECProver, SchnorrECVerifier};
use eczkp::traits::{Prover, Verifier};
use elliptic_curve::SecretKey;
use rand::rngs::OsRng;
use p256::NistP256;

fn main() {
    // Generate a new secret key and public key
    let secret_key = SecretKey::<NistP256>::random(&mut OsRng);
    let public_key = secret_key.public_key();

    // Prover creates a commitment
    let prover = SchnorrECProver::new(&secret_key, &mut OsRng);
    let commitment = prover.commitment();

    // Verifier generates a random challenge
    let verifier = SchnorrECVerifier::new(&public_key, commitment, &mut OsRng);
    let challenge = verifier.challenge();

    // Prover answers the challenge
    let answer = prover.answer(challenge);

    // Verifier verifies the proof
    assert!(verifier.verify(answer).is_ok());
}
```

## API Documentation

For more details about the API, please refer to the [RustDoc documentation](https://docs.rs/eczkp).

## How It Works

In a typical ZKP protocol:
1. **Prover** generates a commitment based on a random nonce.
2. **Verifier** sends a challenge.
3. **Prover** computes the response to the challenge without revealing their secret.
4. **Verifier** checks the response against the challenge to verify the prover's knowledge.

This library implements the above using elliptic curve cryptography, providing safe and efficient abstractions for both the prover and verifier.

## Crate Dependencies

- [`elliptic_curve`](https://crates.io/crates/elliptic_curve): Provides elliptic curve cryptographic operations.
- [`zeroize`](https://crates.io/crates/zeroize): Ensures that sensitive data is securely wiped from memory after use.
- [`rand_core`](https://crates.io/crates/rand_core): Provides traits for secure random number generators.

## License

This project is licensed under the GNU General Public License v3.0. See the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request if you find any bugs or want to propose features.

## Acknowledgments

- Thanks to the developers of `elliptic_curve`, `zeroize` and `rand_core` for providing the core libraries this project is built on.

---

Feel free to reach out for any help or questions!

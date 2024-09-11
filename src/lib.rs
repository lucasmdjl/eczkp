/*
 * eczkp - A library for Zero Knowledge Proof protocols using elliptic curves
 *
 * Copyright (C) 2024 Lucas M. de Jong Larrarte
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

//! # eczkp - A Library for Zero Knowledge Proofs using Elliptic Curves
//!
//! `eczkp` is a cryptographic library for creating and verifying zero-knowledge proofs 
//! based on elliptic curves. This library implements a simple protocol that allows one 
//! party (the prover) to prove knowledge of a secret without revealing it, while the 
//! other party (the verifier) verifies the proof without learning the secret.
//!
//! ## Features
//! - **Prover and Verifier**: Structures for handling the roles of prover and verifier in a zero-knowledge protocol.
//! - **Elliptic Curve Support**: Supports elliptic curve cryptography through the `elliptic_curve` crate.
//! - **Commitment, Challenge, Answer**: Well-defined cryptographic constructs for creating proofs.
//! - **Secure Memory Management**: Leverages the `zeroize` crate to ensure secret data is securely wiped from memory.
//!
//! ## Example Usage
//! Here is a simple example of how to use `eczkp` to perform a zero-knowledge proof with the Schnorr protocol:
//!
//! ```rust
//! use eczkp::schnorr::{Prover, Verifier, Nonce, Challenge};
//! use elliptic_curve::SecretKey;
//! use rand::rngs::OsRng;
//! use p256::NistP256;
//!
//! // Generate a new secret key and public key for the prover
//! let secret_key = SecretKey::<NistP256>::random(&mut OsRng);
//! let public_key = secret_key.public_key();
//!
//! // Prover creates a nonce and commitment
//! let nonce = Nonce::random(&mut OsRng);
//! let prover = Prover::new(secret_key, nonce);
//! let commitment = prover.commitment();
//!
//! // Verifier generates a random challenge
//! let challenge = Challenge::random(&mut OsRng);
//! let verifier = Verifier::new(public_key, commitment, challenge);
//!
//! // Prover computes the answer based on the challenge
//! let answer = prover.answer(challenge);
//!
//! // Verifier verifies the proof
//! assert!(verifier.verify(answer).is_ok());
//! ```
//!
//! ## Crate Dependencies
//! - `elliptic_curve`: Provides elliptic curve operations, used for cryptographic operations.
//! - `zeroize`: Ensures sensitive data such as secrets are wiped from memory after use.
//!
//! ## License
//! This library is licensed under the GNU General Public License v3.0.

/// Module for the Schnorr ZKP protocol.
pub mod schnorr;

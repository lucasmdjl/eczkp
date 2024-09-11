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

use elliptic_curve::group::Curve;
use elliptic_curve::ops::MulByGenerator;
use elliptic_curve::point::PointCompression;
use elliptic_curve::rand_core::CryptoRngCore;
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::{
    CurveArithmetic, Error, FieldBytes, FieldBytesSize, NonZeroScalar, PrimeCurve, PrimeField,
    PublicKey, ScalarPrimitive, SecretKey,
};
use zeroize::Zeroize;

/// Struct responsible for generating zero-knowledge proofs
/// in the protocol.
///
/// # Type Parameters
/// - `C`: The elliptic curve used in the protocol.
pub struct Prover<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    secret: NonZeroScalar<C>,
    nonce: NonZeroScalar<C>,
}

impl<C> Prover<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    /// Creates a new prover instance with the given `secret_key` and `nonce`.
    ///
    /// # Arguments
    /// - `secret_key`: The secret key of the prover.
    /// - `nonce`: A nonce for the proof.
    ///
    /// # Returns
    /// A new `Prover` instance.
    pub fn new(secret_key: SecretKey<C>, nonce: Nonce<C>) -> Self {
        Prover {
            secret: secret_key.into(),
            nonce: nonce.into(),
        }
    }

    /// Computes the prover's commitment, to be sent to the verifier.
    ///
    /// # Returns
    /// A `Commitment` containing the affine point corresponding to the prover's nonce.
    pub fn commitment(&self) -> Commitment<C> {
        Commitment::new(C::ProjectivePoint::mul_by_generator(&self.nonce).to_affine())
    }

    /// Computes the answer to a given challenge in the proof protocol.
    ///
    /// # Arguments
    /// - `challenge`: A challenge from the verifier.
    ///
    /// # Returns
    /// An `Answer` to the challenge.
    pub fn answer(self, challenge: Challenge<C>) -> Answer<C> {
        Answer::new(*self.nonce + *challenge.as_scalar() * *self.secret)
    }
}

impl<C> Zeroize for Prover<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn zeroize(&mut self) {
        self.secret.zeroize();
        self.nonce.zeroize();
    }
}

impl<C> Drop for Prover<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Struct responsible for verifying zero-knowledge proofs
/// in the protocol.
///
/// # Type Parameters
/// - `C`: The elliptic curve used in the protocol.
pub struct Verifier<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    public_key: C::ProjectivePoint,
    commitment: C::ProjectivePoint,
    challenge: Challenge<C>,
}

impl<C> Verifier<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    /// Creates a new verifier with the given `public_key`, `commitment`, and `challenge`.
    ///
    /// # Arguments
    /// - `public_key`: The prover's public key.
    /// - `commitment`: The commitment sent by the prover.
    /// - `challenge`: A challenge to be used for the proof.
    ///
    /// # Returns
    /// A new `Verifier` instance.
    pub fn new(public_key: PublicKey<C>, commitment: Commitment<C>, challenge: Challenge<C>) -> Self {
        Verifier {
            public_key: public_key.to_projective(),
            commitment: commitment.to_affine().into(),
            challenge,
        }
    }

    /// Returns the challenge used by the verifier.
    pub fn challenge(&self) -> Challenge<C> {
        self.challenge
    }
    
    /// Verifies the proof by comparing the prover's answer with the expected result.
    ///
    /// # Arguments
    /// - `answer`: The answer provided by the prover.
    ///
    /// # Returns
    /// `Ok` if the answer is valid, `Err` otherwise.
    pub fn verify(self, answer: Answer<C>) -> Result<(), Error> {
        let point1 = self.commitment + self.public_key * self.challenge.as_scalar();
        let point2 = C::ProjectivePoint::mul_by_generator(answer.as_scalar());
        if point1 == point2 {
            Ok(())
        } else {
            Err(Error)
        }
    }
}

/// Represents the random value the prover commits to in the protocol.
pub struct Nonce<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    scalar: NonZeroScalar<C>,
}

impl<C> Nonce<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    /// Creates a new `Nonce` from the given scalar.
    ///
    /// # Arguments
    /// - `scalar`: A non-zero scalar representing the nonce.
    ///
    /// # Returns
    /// A new `Nonce` instance.
    pub fn new(scalar: NonZeroScalar<C>) -> Self {
        Self { scalar }
    }
    
    /// Generates a random `Nonce` using the given cryptographic random number generator.
    ///
    /// # Arguments
    /// - `rng`: A cryptographic random number generator.
    ///
    /// # Returns
    /// A randomly generated `Nonce`.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self::new(NonZeroScalar::random(rng))
    }

    /// Converts the nonce into a non-zero scalar value.
    ///
    /// # Returns
    /// The corresponding `NonZeroScalar`.
    pub fn to_nonzero_scalar(&self) -> NonZeroScalar<C> {
        self.scalar
    }
}

impl<C> From<NonZeroScalar<C>> for Nonce<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn from(scalar: NonZeroScalar<C>) -> Self {
        Self::new(scalar)
    }
}

impl<C> From<Nonce<C>> for NonZeroScalar<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn from(nonce: Nonce<C>) -> Self {
        nonce.to_nonzero_scalar()
    }
}

impl<C> Zeroize for Nonce<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn zeroize(&mut self) {
        self.scalar.zeroize();
    }
}

impl<C> Drop for Nonce<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    fn drop(&mut self) {
        self.zeroize();
    }
}

/// Represents a cryptographic commitment made by the prover.
pub struct Commitment<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    point: C::AffinePoint,
}

impl<C> Commitment<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    /// Creates a new `Commitment` from a given affine point.
    ///
    /// # Arguments
    /// - `point`: The elliptic curve point representing the commitment.
    ///
    /// # Returns
    /// A new `Commitment`.
    pub fn new(point: C::AffinePoint) -> Self {
        Self { point }
    }

    /// Decodes a commitment from SEC1-encoded bytes.
    ///
    /// # Arguments
    /// - `bytes`: A byte slice containing the SEC1-encoded point.
    ///
    /// # Returns
    /// A `Result` containing a `Commitment` or an `Error` if parsing fails.
    pub fn from_sec1_bytes(bytes: &[u8]) -> Result<Self, Error> {
        let encoded_point = EncodedPoint::<C>::from_bytes(bytes)?;
        Self::from_encoded_point(&encoded_point)
    }

    /// Decodes a `Commitment` from an encoded elliptic curve point.
    ///
    /// # Arguments
    /// - `encoded_point`: The encoded elliptic curve point.
    ///
    /// # Returns
    /// A `Result` containing a `Commitment` or an `Error` if parsing fails.
    pub fn from_encoded_point(encoded_point: &EncodedPoint<C>) -> Result<Self, Error> {
        Option::from(C::AffinePoint::from_encoded_point(encoded_point).map(Self::new))
            .ok_or(Error)
    }

    /// Returns the affine point associated with the commitment.
    pub fn to_affine(&self) -> C::AffinePoint {
        self.point
    }

    /// Encodes the commitment to SEC1-encoded bytes.
    ///
    /// # Returns
    /// A `Vec<u8>` containing the SEC1-encoded commitment.
    pub fn to_sec1_bytes(&self) -> Vec<u8>
    where
        C: PointCompression,
    {
        self.point
            .to_encoded_point(C::COMPRESS_POINTS)
            .as_bytes()
            .to_vec()
    }

    /// Encodes the commitment to an encoded elliptic curve point with optional compression.
    ///
    /// # Arguments
    /// - `compress`: Whether to compress the point.
    ///
    /// # Returns
    /// The encoded elliptic curve point.
    pub fn to_encoded_point(&self, compress: bool) -> EncodedPoint<C> {
        self.point.to_encoded_point(compress)
    }
}

/// Represents the challenge issued by the verifier in the protocol.
#[derive(Copy, Clone)]
pub struct Challenge<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    // We use a possibly-zero scalar because the challenge might have been generated by other libraries that allow it.
    scalar: C::Scalar,
}

impl<C> Challenge<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    /// Generates a random challenge using the given cryptographic random number generator.
    ///
    /// # Arguments
    /// - `rng`: A cryptographic random number generator.
    ///
    /// # Returns
    /// A new `Challenge` instance.
    pub fn random(rng: &mut impl CryptoRngCore) -> Self {
        Self {
            // We use a random non-zero scalar because the zero scalar would allow any prover to submit a valid answer.
            scalar: ScalarPrimitive::from(NonZeroScalar::<C>::random(rng)).into(),
        }
    }

    /// Decodes a `Challenge` from raw field bytes.
    ///
    /// # Arguments
    /// - `bytes`: The field bytes.
    ///
    /// # Returns
    /// A `Result` containing a `Challenge` or an `Error` if parsing fails.
    pub fn from_bytes(bytes: &FieldBytes<C>) -> Result<Self, Error> {
        Option::from(ScalarPrimitive::from_bytes(bytes).map(|scalar| Self {
            scalar: scalar.into(),
        }))
        .ok_or(Error)
    }

    /// Decodes a `Challenge` from a big-endian byte slice.
    ///
    /// # Arguments
    /// - `bytes`: A byte slice.
    ///
    /// # Returns
    /// A `Result` containing a `Challenge` or an `Error` if parsing fails.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        ScalarPrimitive::from_slice(bytes).map(|scalar| Self {
            scalar: scalar.into(),
        })
    }

    /// Returns the scalar value associated with the challenge.
    pub fn as_scalar(&self) -> &C::Scalar {
        &self.scalar
    }

    /// Encodes the challenge to field bytes.
    ///
    /// # Returns
    /// The challenge represented as field bytes.
    pub fn to_bytes(&self) -> FieldBytes<C> {
        self.scalar.to_repr()
    }
}

/// Represents the prover's response to the verifier's challenge.
pub struct Answer<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    scalar: C::Scalar,
}

impl<C> Answer<C>
where
    C: CurveArithmetic + PrimeCurve,
    FieldBytesSize<C>: ModulusSize,
    C::AffinePoint: FromEncodedPoint<C> + ToEncodedPoint<C>,
{
    /// Creates a new `Answer` from the given scalar value.
    ///
    /// # Arguments
    /// - `scalar`: The scalar value representing the answer.
    ///
    /// # Returns
    /// A new `Answer`.
    pub fn new(scalar: C::Scalar) -> Self {
        Self { scalar }
    }

    /// Decodes an `Answer` from raw field bytes.
    ///
    /// # Arguments
    /// - `bytes`: A byte slice representing the field bytes.
    ///
    /// # Returns
    /// A `Result` containing an `Answer` or an `Error` if parsing fails.
    pub fn from_bytes(bytes: &FieldBytes<C>) -> Result<Self, Error> {
        Option::from(ScalarPrimitive::from_bytes(bytes).map(|scalar| Self {
            scalar: scalar.into(),
        }))
        .ok_or(Error)
    }

    /// Decodes an `Answer` from a big-endian byte slice.
    ///
    /// # Arguments
    /// - `bytes`: A byte slice.
    ///
    /// # Returns
    /// A `Result` containing an `Answer` or an `Error` if parsing fails.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, Error> {
        ScalarPrimitive::from_slice(bytes)
            .map(|scalar| Self {
                scalar: scalar.into(),
            })
            .map_err(|_| Error)
    }

    /// Returns the scalar value associated with the answer.
    pub fn as_scalar(&self) -> &C::Scalar {
        &self.scalar
    }

    /// Encodes the answer to field bytes.
    ///
    /// # Returns
    /// The answer represented as field bytes.
    pub fn to_bytes(&self) -> FieldBytes<C> {
        self.scalar.to_repr()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::NistP256;
    use std::sync::mpsc::channel;
    use std::thread;
    use rand::rngs::OsRng;

    #[test]
    fn it_works() {
        // Generate a new keypair
        let secret_key = SecretKey::<NistP256>::random(&mut OsRng);
        let public_key = secret_key.public_key();

        // Create the communication channels
        let (client_sender, server_receiver) = channel::<String>();
        let (server_sender, client_receiver) = channel::<String>();

        let client_thread = thread::spawn(move || {
            let nonce = Nonce::random(&mut OsRng);
            let prover = Prover::new(secret_key, nonce);
            let commitment = prover.commitment();
            let commitment = hex::encode(commitment.to_sec1_bytes());
            client_sender.send(commitment).unwrap();
            let challenge = client_receiver.recv().unwrap();
            let challenge = hex::decode(challenge).unwrap();
            let answer = prover.answer(Challenge::from_slice(&challenge).unwrap());
            let answer = hex::encode(answer.to_bytes());
            client_sender.send(answer).unwrap();
        });

        let server_thread = thread::spawn(move || {
            let commitment = server_receiver.recv().unwrap();
            let commitment = hex::decode(commitment).unwrap();
            let verifier = Verifier::new(
                public_key,
                Commitment::from_sec1_bytes(&commitment).unwrap(),
                Challenge::random(&mut OsRng),
            );
            let challenge = verifier.challenge();
            let challenge = hex::encode(challenge.to_bytes());
            server_sender.send(challenge).unwrap();
            let answer = server_receiver.recv().unwrap();
            let answer = hex::decode(answer).unwrap();
            verifier
                .verify(Answer::from_slice(&answer).unwrap())
                .unwrap();
        });

        // Wait for the threads to finish
        client_thread.join().unwrap();
        server_thread.join().unwrap();
    }
}

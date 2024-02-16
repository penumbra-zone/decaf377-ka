// Requires nightly.
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
#![cfg_attr(not(feature = "std"), no_std)]

use core::fmt;

use decaf377;
use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroize as _;
use zeroize_derive::Zeroize;

/// A public key sent to the counterparty in the key agreement protocol.
///
/// This is a refinement type around `[u8; 32]` that marks the bytes as being a
/// public key.  Not all 32-byte arrays are valid public keys; invalid public
/// keys will error during key agreement.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Public(pub [u8; 32]);

/// A secret key used to perform key agreement using the counterparty's public key.
#[derive(Clone, Zeroize, PartialEq, Eq)]
#[zeroize(drop)]
pub struct Secret(decaf377::Fr);

/// The shared secret derived at the end of the key agreement protocol.
#[derive(PartialEq, Eq, Clone, Zeroize)]
#[zeroize(drop)]
pub struct SharedSecret(pub [u8; 32]);

/// An error during key agreement.
#[cfg_attr(feature = "std", derive(Debug))]
pub enum Error {
    InvalidPublic(Public),
    InvalidSecret,
    SliceLenError,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPublic(_) => f.write_str("Invalid public key"),
            Self::InvalidSecret => f.write_str("Invalid secret key"),
            Self::SliceLenError => f.write_str("Supplied bytes are incorrect length"),
        }
    }
}

impl Secret {
    /// Generate a new secret key using `rng`.
    pub fn new<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        Self(decaf377::Fr::rand(rng))
    }

    /// Use the supplied field element as the secret key directly.
    ///
    /// # Warning
    ///
    /// This function exists to allow custom key derivation; it's the caller's
    /// responsibility to ensure that the input was generated securely.
    pub fn new_from_field(sk: decaf377::Fr) -> Self {
        Self(sk)
    }

    /// Derive a public key for this secret key, using the conventional
    /// `decaf377` generator.
    pub fn public(&self) -> Public {
        self.diversified_public(&decaf377::Element::GENERATOR)
    }

    /// Derive a diversified public key for this secret key, using the provided
    /// `diversified_generator`.
    ///
    /// Since key agreement does not depend on the basepoint, only on the secret
    /// key and the public key, a single secret key can correspond to many
    /// different (unlinkable) public keys.
    pub fn diversified_public(&self, diversified_generator: &decaf377::Element) -> Public {
        Public((self.0 * diversified_generator).vartime_compress().into())
    }

    /// Perform key agreement with the provided public key.
    ///
    /// Fails if the provided public key is invalid.
    pub fn key_agreement_with(&self, other: &Public) -> Result<SharedSecret, Error> {
        let pk = decaf377::Encoding(other.0)
            .vartime_decompress()
            .map_err(|_| Error::InvalidPublic(*other))?;

        Ok(SharedSecret((self.0 * pk).vartime_compress().into()))
    }

    /// Convert this shared secret to bytes.
    ///
    /// Convenience wrapper around an [`Into`] impl.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.into()
    }
}

impl TryFrom<&[u8]> for Public {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Public, Error> {
        let bytes: [u8; 32] = slice.try_into().map_err(|_| Error::SliceLenError)?;
        Ok(Public(bytes))
    }
}

impl TryFrom<&[u8]> for Secret {
    type Error = Error;

    fn try_from(slice: &[u8]) -> Result<Secret, Error> {
        let bytes: [u8; 32] = slice.try_into().map_err(|_| Error::SliceLenError)?;
        bytes.try_into()
    }
}

impl TryFrom<[u8; 32]> for Secret {
    type Error = Error;
    fn try_from(bytes: [u8; 32]) -> Result<Secret, Error> {
        let x = decaf377::Fr::from_bytes_checked(&bytes).map_err(|_| Error::InvalidSecret)?;
        Ok(Secret(x))
    }
}

impl TryFrom<[u8; 32]> for SharedSecret {
    type Error = Error;
    fn try_from(bytes: [u8; 32]) -> Result<SharedSecret, Error> {
        decaf377::Encoding(bytes)
            .vartime_decompress()
            .map_err(|_| Error::InvalidSecret)?;

        Ok(SharedSecret(bytes))
    }
}

impl From<&Secret> for [u8; 32] {
    fn from(s: &Secret) -> Self {
        s.0.to_bytes()
    }
}

#[cfg(feature = "std")]
mod std_only {
    use super::*;

    impl std::fmt::Debug for Public {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_fmt(format_args!(
                "decaf377_ka::Public({})",
                hex::encode(&self.0[..])
            ))
        }
    }

    impl std::fmt::Debug for Secret {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            let bytes = self.0.to_bytes();
            f.write_fmt(format_args!(
                "decaf377_ka::Secret({})",
                hex::encode(&bytes[..])
            ))
        }
    }

    impl std::fmt::Debug for SharedSecret {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_fmt(format_args!(
                "decaf377_ka::SharedSecret({})",
                hex::encode(&self.0[..])
            ))
        }
    }
}

#[cfg(feature = "std")]
pub use std_only::*;

#[cfg(all(test, feature = "std"))]
mod test {
    use super::*;

    use proptest::prelude::*;

    fn fq_strategy() -> BoxedStrategy<decaf377::Fq> {
        any::<[u8; 32]>()
            .prop_map(|bytes| decaf377::Fq::from_le_bytes_mod_order(&bytes[..]))
            .boxed()
    }

    fn fr_strategy() -> BoxedStrategy<decaf377::Fr> {
        any::<[u8; 32]>()
            .prop_map(|bytes| decaf377::Fr::from_le_bytes_mod_order(&bytes[..]))
            .boxed()
    }

    proptest! {
        #[test]
        fn key_agreement_works(
            alice_sk in fr_strategy(),
            bob_sk in fr_strategy(),
        ) {
            let alice_sk = Secret::new_from_field(alice_sk);
            let bob_sk = Secret::new_from_field(bob_sk);

            let alice_pk = alice_sk.public();
            let bob_pk = bob_sk.public();

            let alice_ss = alice_sk.key_agreement_with(&bob_pk).unwrap();
            let bob_ss = bob_sk.key_agreement_with(&alice_pk).unwrap();

            assert_eq!(alice_ss, bob_ss);
        }

        #[test]
        fn diversified_key_agreement_works(
            alice_sk in fr_strategy(),
            bob_sk in fr_strategy(),
            div1 in fq_strategy(),
            div2 in fq_strategy(),
        ) {
            let alice_sk = Secret::new_from_field(alice_sk);
            let bob_sk = Secret::new_from_field(bob_sk);

            let gen1 = decaf377::Element::encode_to_curve(&div1);
            let gen2 = decaf377::Element::encode_to_curve(&div2);

            let alice_pk1 = alice_sk.diversified_public(&gen1);
            let alice_pk2 = alice_sk.diversified_public(&gen2);

            let bob_pk1 = bob_sk.diversified_public(&gen1);
            let bob_pk2 = bob_sk.diversified_public(&gen2);

            let bob_ss1 = bob_sk.key_agreement_with(&alice_pk1).unwrap();
            let bob_ss2 = bob_sk.key_agreement_with(&alice_pk2).unwrap();

            let alice_ss1 = alice_sk.key_agreement_with(&bob_pk1).unwrap();
            let alice_ss2 = alice_sk.key_agreement_with(&bob_pk2).unwrap();

            assert_eq!(alice_ss1, bob_ss1);
            assert_eq!(alice_ss2, bob_ss2);
        }
    }
}

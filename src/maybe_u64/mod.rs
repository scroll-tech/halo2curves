use ff::PrimeField;
use rand_core::RngCore;
use serde::{Deserialize, Serialize};

mod arithmetic;
mod conversion;
mod field;
mod field_ext;
mod misc;
mod prime_field;
mod serdes;

#[cfg(test)]
mod tests;

#[derive(Clone, Copy, Debug, Eq, Hash, Serialize, Deserialize)]
/// Struct for a 256-bits field elements.
/// - U64: if the element is less than 1<<64
/// - Full: otherwise
///
/// This allows for faster computation with u64 ops.
pub enum MaybeU64<F>
where
    F: PrimeField<Repr = [u8; 32]>,
{
    U64(u64),
    Full(F),
}

pub trait MaybeU64Coversion {
    /// Convert a u64 to a full field element
    fn to_full(&self) -> Self;
    /// Convert a full field element into u64 format.
    fn to_u64(&self) -> Self;
    /// random u64
    fn random_u64(rng: impl RngCore) -> Self;
    /// random field element
    fn random_field(rng: impl RngCore) -> Self;
}

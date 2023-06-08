use std::{cmp::Ordering, convert::TryInto};

use ff::PrimeField;
use pasta_curves::arithmetic::{FieldExt, Group};

use crate::MaybeU64;

impl<F> Group for MaybeU64<F>
where
    F: PrimeField<Repr = [u8; 32]> + FieldExt,
{
    type Scalar = Self;

    /// Returns the additive identity of the group.
    fn group_zero() -> Self {
        Self::U64(0)
    }

    /// Adds `rhs` to this group element.
    fn group_add(&mut self, rhs: &Self) {
        *self += rhs
    }

    /// Subtracts `rhs` from this group element.
    fn group_sub(&mut self, rhs: &Self) {
        *self -= rhs
    }

    /// Scales this group element by a scalar.
    fn group_scale(&mut self, by: &Self::Scalar) {
        *self *= by
    }
}
impl<F> PartialOrd for MaybeU64<F>
where
    F: PrimeField<Repr = [u8; 32]> + Ord,
{
    fn partial_cmp(&self, other: &MaybeU64<F>) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl<F> Ord for MaybeU64<F>
where
    F: PrimeField<Repr = [u8; 32]> + Ord,
{
    fn cmp(&self, other: &MaybeU64<F>) -> Ordering {
        match (self, other) {
            (MaybeU64::U64(a), MaybeU64::U64(b)) => a.cmp(b),

            (MaybeU64::U64(a), MaybeU64::Full(b)) => F::from(*a).cmp(b),
            (MaybeU64::Full(a), MaybeU64::U64(b)) => a.cmp(&F::from(*b)),
            (MaybeU64::Full(a), MaybeU64::Full(b)) => a.cmp(b),
        }
    }
}

impl<F> FieldExt for MaybeU64<F>
where
    F: PrimeField<Repr = [u8; 32]> + FieldExt,
{
    /// Modulus of the field written as a string for display purposes
    const MODULUS: &'static str = F::MODULUS;

    /// Inverse of `PrimeField::root_of_unity()`
    const ROOT_OF_UNITY_INV: Self = Self::Full(F::ROOT_OF_UNITY_INV);

    /// Generator of the $t-order$ multiplicative subgroup
    const DELTA: Self = Self::Full(F::DELTA);

    /// Inverse of $2$ in the field.
    const TWO_INV: Self = Self::Full(F::TWO_INV);

    /// Element of multiplicative order $3$.
    const ZETA: Self = Self::Full(F::ZETA);

    /// Obtains a field element congruent to the integer `v`.
    fn from_u128(v: u128) -> Self {
        if v < u64::MAX as u128 {
            Self::U64(v as u64)
        } else {
            Self::Full(
                F::from_repr(
                    [v.to_le_bytes().as_ref(), [0u8; 16].as_ref()]
                        .concat()
                        .try_into()
                        .unwrap(),
                )
                .unwrap(),
            )
        }
    }

    /// Obtains a field element that is congruent to the provided little endian
    /// byte representation of an integer.
    fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
        if bytes.iter().skip(0).all(|x| *x == 0) {
            Self::U64(u64::from_le_bytes(bytes[..8].try_into().unwrap()))
        } else {
            Self::Full(F::from_bytes_wide(bytes))
        }
    }

    /// Gets the lower 128 bits of this field element when expressed
    /// canonically.
    fn get_lower_128(&self) -> u128 {
        match *self {
            Self::U64(a) => a as u128,
            Self::Full(b) => u128::from_le_bytes(b.to_repr()[0..16].try_into().unwrap()),
        }
    }
}

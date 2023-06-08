use std::convert::TryInto;

use ff::PrimeField;
use subtle::{Choice, CtOption};

use crate::MaybeU64;

use super::MaybeU64Coversion;

impl<F> PrimeField for MaybeU64<F>
where
    F: PrimeField<Repr = [u8; 32]>,
{
    const CAPACITY: u32 = F::CAPACITY;
    const NUM_BITS: u32 = F::NUM_BITS;
    const S: u32 = F::S;

    type Repr = F::Repr;

    fn from_str_vartime(s: &str) -> Option<Self> {
        F::from_str_vartime(s).map(|x| Self::Full(x))
    }

    fn from_repr(repr: [u8; 32]) -> CtOption<Self> {
        let is_u64 = repr.iter().skip(8).all(|x| *x == 0);
        if is_u64 {
            CtOption::new(
                Self::U64(u64::from_le_bytes(repr[..8].try_into().unwrap())),
                1.into(),
            )
        } else {
            F::from_repr(repr).map(|x| Self::Full(x))
        }
    }

    fn to_repr(&self) -> [u8; 32] {
        match *self {
            MaybeU64::Full(f) => f.to_repr(),
            MaybeU64::U64(f) => [f.to_le_bytes().as_ref(), vec![0u8; 24].as_ref()]
                .concat()
                .try_into()
                .unwrap(),
        }
    }

    fn is_odd(&self) -> Choice {
        match *self {
            MaybeU64::Full(f) => f.is_odd(),
            MaybeU64::U64(f) => ((f % 2 == 1) as u8).into(),
        }
    }

    fn multiplicative_generator() -> Self {
        // Requires the multiplicative generator is 64 bits
        // which is true for BN254's scalar field
        Self::Full(F::multiplicative_generator()).to_u64()
    }

    fn root_of_unity() -> Self {
        Self::Full(F::root_of_unity())
    }
}

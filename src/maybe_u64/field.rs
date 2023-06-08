use ff::{Field, PrimeField};
use rand_core::RngCore;
use subtle::CtOption;

use crate::MaybeU64;

impl<F> Field for MaybeU64<F>
where
    F: PrimeField<Repr = [u8; 32]>,
{
    fn random(rng: impl RngCore) -> Self {
        Self::Full(F::random(rng))
    }

    fn zero() -> Self {
        Self::U64(0)
    }

    fn one() -> Self {
        Self::U64(1)
    }

    fn square(&self) -> Self {
        self * self
    }

    fn double(&self) -> Self {
        self + self
    }

    fn invert(&self) -> CtOption<Self> {
        match *self {
            MaybeU64::U64(a) => F::from(a).invert().map(|x| MaybeU64::Full(x)),
            MaybeU64::Full(a) => a.invert().map(|x| MaybeU64::Full(x)),
        }
    }

    fn sqrt(&self) -> CtOption<Self> {
        match *self {
            MaybeU64::U64(a) => F::from(a).sqrt().map(|x| MaybeU64::Full(x)),
            MaybeU64::Full(a) => a.sqrt().map(|x| MaybeU64::Full(x)),
        }
    }
}

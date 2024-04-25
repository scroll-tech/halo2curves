extern "C" {
    fn syscall_bn254_scalar_arith(pq: *mut u32, op: u32);
}

/// Fr is stored in canonical form as its arithmetic is
/// redirected to syscall_bn254_scalar_arith.
pub struct Fr(pub(crate) [u32; 8]);

const MODULUS: Fr = Fr([
    0xf0000001,
    0x43e1f593, 
    0x79b97091,
    0x2833e848,
    0x8181585d,
    0xb85045b6,
    0xe131a029,
    0x30644e72,
]);

/// Compute a - (b + borrow), returning the result and the new borrow.
#[inline(always)]
pub(crate) const fn sbb_u32(a: u32, b: u32, borrow: u32) -> (u32, u32) {
    let ret = (a as u64).wrapping_sub((b as u64) + ((borrow >> 31) as u64));
    (ret as u32, (ret >> 32) as u32)
}

impl Fr {
    #[inline]
    pub const fn zero() -> Self {
        Fr([0, 0, 0, 0, 0, 0, 0, 0])
    }

    pub const fn one() -> Self {
        Fr([1, 0, 0, 0, 0, 0, 0, 0])
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> CtOption<Fr> {
        let mut tmp = Fr([0, 0, 0, 0, 0, 0, 0, 0]);

        tmp.0[0] = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
        tmp.0[1] = u32::from_le_bytes(bytes[4..8].try_into().unwrap());
        tmp.0[2] = u32::from_le_bytes(bytes[8..12].try_into().unwrap());
        tmp.0[3] = u32::from_le_bytes(bytes[12..16].try_into().unwrap());
        tmp.0[4] = u32::from_le_bytes(bytes[16..20].try_into().unwrap());
        tmp.0[5] = u32::from_le_bytes(bytes[20..24].try_into().unwrap());
        tmp.0[6] = u32::from_le_bytes(bytes[24..28].try_into().unwrap());
        tmp.0[7] = u32::from_le_bytes(bytes[28..32].try_into().unwrap());

        let (_, borrow) = sbb_u32(tmp.0[0], MODULUS.0[0], 0);
        let (_, borrow) = sbb_u32(tmp.0[1], MODULUS.0[1], borrow);
        let (_, borrow) = sbb_u32(tmp.0[2], MODULUS.0[2], borrow);
        let (_, borrow) = sbb_u32(tmp.0[3], MODULUS.0[3], borrow);
        let (_, borrow) = sbb_u32(tmp.0[4], MODULUS.0[4], borrow);
        let (_, borrow) = sbb_u32(tmp.0[5], MODULUS.0[5], borrow);
        let (_, borrow) = sbb_u32(tmp.0[6], MODULUS.0[6], borrow);
        let (_, borrow) = sbb_u32(tmp.0[7], MODULUS.0[7], borrow);

        let is_some = (borrow as u8) & 1;

        CtOption::new(tmp, Choice::from(is_some))
    }
}

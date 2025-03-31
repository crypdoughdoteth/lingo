use ark_ec::{
    CurveConfig, CurveGroup, PrimeGroup, hashing::HashToCurve, short_weierstrass::SWCurveConfig,
    twisted_edwards::TECurveConfig,
};
use ark_ff::{BigInt, BigInteger, BigInteger256, FftField, UniformRand};
use ark_std::rand;
use std::ops::Mul;

type CurvePoint<C> = <<C as CurveConfig>::ScalarField as Mul<BigInt<4>>>::Output;

#[derive(PartialEq, Eq)]
pub struct Ring<C>
where
    C: ark_ec::CurveConfig + HashToCurve<C> + CurveGroup,
    <C as CurveConfig>::ScalarField: CurveGroup,
    <C as CurveConfig>::ScalarField: Mul<BigInt<4>>,
    <<C as CurveConfig>::ScalarField as Mul<BigInt<4>>>::Output: CurveGroup,
{
    keys: Vec<CurvePoint<C>>,
}

impl<C> Ring<C>
where
    C: ark_ec::CurveConfig + HashToCurve<C> + CurveGroup,
    <C as CurveConfig>::ScalarField: CurveGroup,
    <C as CurveConfig>::ScalarField: Mul<BigInt<4>>,
    <<C as CurveConfig>::ScalarField as Mul<BigInt<4>>>::Output: CurveGroup,
{
    pub fn new(ring_size: usize, private_key: BigInteger256, index: usize) -> Ring<C> {
        assert!(index < ring_size);
        assert!(!BigInteger::is_zero(&private_key));

        let public_key: CurvePoint<C> =
            <<C as CurveConfig>::ScalarField>::GENERATOR.mul(private_key);
        let mut public_keys: Vec<CurvePoint<C>> = (0..ring_size)
            .into_iter()
            .map(|_| {
                let mut rng = rand::thread_rng();
                let pk = BigInteger256::rand(&mut rng);
                <<C as CurveConfig>::ScalarField>::GENERATOR.mul(pk)
            })
            .collect();

        public_keys.push(public_key);
        public_keys.swap(index, ring_size - 1);
        Ring { keys: public_keys }
    }

    // does order matter for set of pubkeys in this method outside of the one we designate at a
    // given index?
    pub fn from_pubkeys(
        pubs: &[CurvePoint<C>],
        private_key: BigInteger256,
        index: usize,
    ) -> Ring<C> {
        let size = pubs.len() + 1;
        assert!(!private_key.is_zero());
        assert!(index < size);
        let mut ring: Vec<CurvePoint<C>> = Vec::with_capacity(size);
        let public_key = <C as CurveConfig>::ScalarField::GENERATOR.mul(private_key);
        ring.copy_from_slice(&pubs[..index]);
        ring[index] = public_key;
        ring.copy_from_slice(&pubs[index + 1..]);
        Ring { keys: ring }
    }

    pub fn from_fixed_pubkeys(public_keys: Vec<CurvePoint<C>>) -> Ring<C> {
        Ring { keys: public_keys }
    }

    pub fn size(&self) -> usize {
        self.keys.len()
    }
}

#[derive(PartialEq, Eq)]
pub struct RingSignature<'a, B, C>
where
    B: BigInteger,
    C: ark_ec::CurveConfig + HashToCurve<C> + CurveGroup,
    <C as CurveConfig>::ScalarField: CurveGroup,
    <C as CurveConfig>::ScalarField: Mul<BigInt<4>>,
    <<C as CurveConfig>::ScalarField as Mul<BigInt<4>>>::Output: CurveGroup,
{
    pub ring: &'a Ring<C>,
    pub challenge: B,
    pub ring_sig_vals: Vec<B>,
    pub image: CurvePoint<C>,
}

impl<'a, B, C> RingSignature<'a, B, C>
where
    B: BigInteger,
    C: ark_ec::CurveConfig + HashToCurve<C> + CurveGroup,
    <C as CurveConfig>::ScalarField: CurveGroup,
    <C as CurveConfig>::ScalarField: Mul<BigInt<4>>,
    <<C as CurveConfig>::ScalarField as Mul<BigInt<4>>>::Output: CurveGroup,
{
    pub fn public_keys(&self) -> &[CurvePoint<C>] {
        &self.ring.keys
    }

    pub fn ring(&self) -> &Ring<C> {
        self.ring
    }
}

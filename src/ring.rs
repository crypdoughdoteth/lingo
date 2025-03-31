use std::marker::PhantomData;
use ark_ec::{
    AffineRepr, CurveConfig, CurveGroup,
    short_weierstrass::{Affine, SWCurveConfig},
    twisted_edwards::TECurveConfig,
};
use ark_ed25519::EdwardsConfig;
use ark_ff::{BigInteger, BigInteger256, UniformRand};
use ark_secp256k1::Config;
use ark_std::rand;

#[derive(PartialEq, Eq)]
pub struct Ring<P, C>
where
    P: ark_ec::AffineRepr,
    C: ark_ec::CurveConfig,
{
    keys: Vec<P>,
    curve: PhantomData<C>,
}

/// Ed25519 curve impl
impl Ring<ark_ec::twisted_edwards::Affine<EdwardsConfig>, EdwardsConfig> {
    pub fn new(
        ring_size: usize,
        private_key: BigInteger256,
        index: usize,
    ) -> Ring<ark_ec::twisted_edwards::Affine<EdwardsConfig>, EdwardsConfig> {
        assert!(index < ring_size);
        assert!(!private_key.is_zero());
        let public_key = EdwardsConfig::GENERATOR.mul_bigint(private_key).into_affine();
        let mut public_keys: Vec<ark_ec::twisted_edwards::Affine<EdwardsConfig>> = (0..ring_size)
            .into_iter()
            .map(|_| {
                let mut rng = rand::thread_rng();
                let pk = BigInteger256::rand(&mut rng);
                EdwardsConfig::GENERATOR.mul_bigint(pk).into_affine()
            })
            .collect();
        public_keys.push(public_key);
        public_keys.swap(index, ring_size - 1);
        Ring {
            keys: public_keys,
            curve: PhantomData::<EdwardsConfig>,
        }
    }

    pub fn from_pubkeys(
        pubs: &[ark_ec::twisted_edwards::Affine<EdwardsConfig>],
        private_key: BigInteger256,
        index: usize,
    ) -> Ring<ark_ec::twisted_edwards::Affine<EdwardsConfig>, EdwardsConfig> {
        let size = pubs.len() + 1;
        assert!(!private_key.is_zero());
        assert!(index < size);
        let mut ring: Vec<ark_ec::twisted_edwards::Affine<EdwardsConfig>> =
            Vec::with_capacity(size);
        let public_key = EdwardsConfig::GENERATOR
            .mul_bigint(private_key)
            .into_affine();
        ring.copy_from_slice(&pubs[0..index]);
        ring[index] = public_key;
        ring.copy_from_slice(&pubs[index + 1..]);
        Ring {
            keys: ring,
            curve: PhantomData::<EdwardsConfig>,
        }
    }

    pub fn from_fixed_pubkeys(
        public_keys: Vec<ark_ec::twisted_edwards::Affine<EdwardsConfig>>,
    ) -> Ring<ark_ec::twisted_edwards::Affine<EdwardsConfig>, EdwardsConfig> {
        assert!(public_keys.len() > 0);
        Ring {
            keys: public_keys,
            curve: PhantomData::<EdwardsConfig>,
        }
    }
}

/// Secp256k1 Curve
impl Ring<Affine<Config>, Config> {
    pub fn new(
        ring_size: usize,
        private_key: BigInteger256,
        index: usize,
    ) -> Ring<Affine<Config>, Config> {
        assert!(index < ring_size);
        assert!(!private_key.is_zero());
        let public_key = Config::GENERATOR.mul_bigint(private_key).into_affine();
        let mut public_keys: Vec<Affine<Config>> = (0..ring_size)
            .into_iter()
            .map(|_| {
                let mut rng = rand::thread_rng();
                let pk = BigInteger256::rand(&mut rng);
                Config::GENERATOR.mul_bigint(pk).into_affine()
            })
            .collect();
        public_keys.push(public_key);
        public_keys.swap(index, ring_size - 1);
        Ring {
            keys: public_keys,
            curve: PhantomData::<Config>,
        }
    }

    // does order of pubkeys matter here??
    pub fn from_pubkeys(
        pubs: &[Affine<Config>],
        private_key: BigInteger256,
        index: usize,
    ) -> Ring<Affine<Config>, Config> {
        let size = pubs.len() + 1;
        assert!(!private_key.is_zero());
        assert!(index < size);
        let mut ring: Vec<Affine<Config>> = Vec::with_capacity(size);
        let public_key = Config::GENERATOR.mul_bigint(private_key).into_affine();
        ring[index] = public_key;
        ring.copy_from_slice(&pubs[0..index]);
        ring.copy_from_slice(&pubs[index + 1..]);
        Ring {
            keys: ring,
            curve: PhantomData::<Config>,
        }
    }

    pub fn from_fixed_pubkeys(public_keys: Vec<Affine<Config>>) -> Ring<Affine<Config>, Config> {
        assert!(public_keys.len() > 0);
        Ring {
            keys: public_keys,
            curve: PhantomData::<Config>,
        }
    }
}

impl<P, C> Ring<P, C>
where
    P: ark_ec::AffineRepr,
    C: CurveConfig,
{
    pub fn size(&self) -> usize {
        self.keys.len()
    }
}

#[derive(PartialEq, Eq)]
pub struct RingSignature<'a, P, B, C>
where
    B: BigInteger,
    P: AffineRepr,
    C: CurveConfig,
{
    pub ring: &'a Ring<P, C>,
    pub challenge: B,
    pub ring_sig_vals: Vec<B>,
    pub image: P,
    pub curve: PhantomData<C>,
}

impl<'a, P, B, C> RingSignature<'a, P, B, C>
where
    B: BigInteger,
    P: AffineRepr,
    C: CurveConfig,
{
    pub fn public_keys(&self) -> &[P] {
        &self.ring.keys
    }

    pub fn ring(&self) -> &Ring<P, C> {
        self.ring
    }
}

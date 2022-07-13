mod arithmetic;
mod expression;
mod transcript;

use std::fmt::Debug;
use crate::protocol::Protocol;
use rand::RngCore;

use crate::protocol::compile;

pub use arithmetic::{
    batch_invert, batch_invert_and_mul, fe_from_limbs, fe_to_limbs, Curve, Domain, Field, FieldOps,
    Fraction, Group, GroupEncoding, GroupOps, PrimeCurveAffine, PrimeField, Rotation,
    UncompressedEncoding,
};
pub use expression::{CommonPolynomial, CommonPolynomialEvaluation, Expression, Query};
use halo2_wrong::{
	halo2::{
		plonk::{keygen_pk, keygen_vk, Circuit, create_proof},
		poly::commitment::CommitmentScheme,
		transcript::{EncodedChallenge, TranscriptWriterBuffer},
	},
	curves::{pairing::Engine, CurveAffine},

};
use halo2_wrong_ecc::halo2::{
	poly::commitment::Prover,
	plonk::ProvingKey
};
pub use transcript::{Transcript, TranscriptRead};
use crate::native::Snark;

#[macro_export]
macro_rules! hex {
    ($bytes:expr) => {
        hex::encode(
            $bytes
                .iter()
                .position(|byte| *byte != 0)
                .map_or(vec![0], |pos| $bytes.into_iter().skip(pos).collect()),
        )
    };
}

#[macro_export]
macro_rules! collect_slice {
    ($vec:ident) => {
        let $vec = $vec.iter().map(|vec| vec.as_slice()).collect::<Vec<_>>();
    };
    ($vec:ident, 2) => {
        let $vec = $vec
            .iter()
            .map(|vec| {
                collect_slice!(vec);
                vec
            })
            .collect::<Vec<_>>();
        let $vec = $vec.iter().map(|vec| vec.as_slice()).collect::<Vec<_>>();
    };
}

pub fn prepare<E: Engine + Debug, S: CommitmentScheme, C: Circuit<S::Scalar>>(
	circuit: &C,
	k: u32,
	n: usize,
	accumulator_indices: Option<Vec<(usize, usize)>>
) -> (S::ParamsProver, ProvingKey<S::Curve>, Protocol<<S::Curve as CurveAffine>::CurveExt>) {
	let params = S::new_params(k);
	let vk = keygen_vk::<S, _>(&params, circuit).unwrap();
	let pk = keygen_pk::<S, _>(&params, vk, circuit).unwrap();

	let protocol = compile::<S::Curve>(pk.get_vk(), n, accumulator_indices);

	(params, pk, protocol)
}

pub fn accumulate_snark<
	'a,
	E: Engine,
	S: CommitmentScheme,
	EC: EncodedChallenge<S::Curve>,
	TW: TranscriptWriterBuffer<Vec<u8>, S::Curve, EC>,
	P: Prover<'a, S>,
	C: Circuit<S::Scalar>,
	R: RngCore,
>(
	params: &'a S::ParamsProver,
	pk: &ProvingKey<S::Curve>,
	circuits: &[C],
	instances: &[&[&[S::Scalar]]],
	protocol: Protocol<<S::Curve as CurveAffine>::CurveExt>,
	mut rng: R,
) -> Snark<<S::Curve as CurveAffine>::CurveExt> {
	let mut transcript = TW::init(Vec::new());
	create_proof::<S, P, _, _, _, _>(
		params,
		pk,
		circuits,
		instances,
		&mut rng,
		&mut transcript,
	)
	.unwrap();
	let proof = transcript.finalize();

	let instances_vec = instances
		.to_vec()
		.iter()
		.map(|inner|
			inner
			.to_vec()
			.iter()
			.map(|inner_inner| inner_inner.to_vec())
			.collect::<Vec<_>>()
		)
		.collect::<Vec<_>>();
	Snark::new(
		protocol,
		instances_vec.into_iter().flatten().collect::<Vec<_>>(),
		proof,
	)
}
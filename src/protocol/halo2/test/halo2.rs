use crate::{
    collect_slice, halo2_create_snark, halo2_native_accumulate, halo2_native_verify, halo2_prepare,
    loader::{halo2, native::NativeLoader},
    protocol::{
        halo2::{
            test::{MainGateWithRange, MainGateWithRangeConfig, Snark, StandardPlonk, BITS, LIMBS},
            util::halo2::ChallengeScalar,
        },
        Protocol,
    },
    scheme::{self, AccumulationScheme, ShplonkAccumulationScheme},
    util::{fe_to_limbs, Curve, Group, PrimeCurveAffine},
};
use halo2_curves::bn256::{Fr, G1Affine, G1};
use halo2_proofs::{
    circuit::{floor_planner::V1, Layouter, Value},
    plonk,
    plonk::Circuit,
    poly::{
        commitment::ParamsProver,
        kzg::{
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::BatchVerifier,
        },
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer},
};
use halo2_wrong_ecc;
use halo2_wrong_maingate::RegionCtx;
use halo2_wrong_transcript::NativeRepresentation;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::rc::Rc;

const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 57;

type BaseFieldEccChip<C> = halo2_wrong_ecc::BaseFieldEccChip<C, LIMBS, BITS>;
type Halo2Loader<'a, 'b, C> = halo2::Halo2Loader<'a, 'b, C, LIMBS, BITS>;
type PoseidonTranscript<C, L, S, B> =
    halo2::PoseidonTranscript<C, L, S, B, NativeRepresentation, LIMBS, BITS, T, RATE, R_F, R_P>;
type SameCurveAccumulation<C, L> = scheme::SameCurveAccumulation<C, L, LIMBS, BITS>;

pub struct SnarkWitness<C: Curve> {
    protocol: Protocol<C>,
    statements: Vec<Vec<Value<<C as Group>::Scalar>>>,
    proof: Value<Vec<u8>>,
}

impl<C: Curve> From<Snark<C>> for SnarkWitness<C> {
    fn from(snark: Snark<C>) -> Self {
        Self {
            protocol: snark.protocol,
            statements: snark
                .statements
                .into_iter()
                .map(|statements| statements.into_iter().map(Value::known).collect::<Vec<_>>())
                .collect(),
            proof: Value::known(snark.proof),
        }
    }
}

impl<C: Curve> SnarkWitness<C> {
    pub fn without_witnesses(&self) -> Self {
        SnarkWitness {
            protocol: self.protocol.clone(),
            statements: self
                .statements
                .iter()
                .map(|statements| vec![Value::unknown(); statements.len()])
                .collect(),
            proof: Value::unknown(),
        }
    }
}

pub fn accumulate<'a, 'b>(
    loader: &Rc<Halo2Loader<'a, 'b, G1Affine>>,
    stretagy: &mut SameCurveAccumulation<G1, Rc<Halo2Loader<'a, 'b, G1Affine>>>,
    snark: &SnarkWitness<G1>,
) -> Result<(), plonk::Error> {
    let mut transcript = PoseidonTranscript::<_, Rc<Halo2Loader<G1Affine>>, _, _>::new(
        loader,
        snark.proof.as_ref().map(|proof| proof.as_slice()),
    );
    let statements = snark
        .statements
        .iter()
        .map(|statements| {
            statements
                .iter()
                .map(|statement| loader.assign_scalar(*statement))
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    ShplonkAccumulationScheme::accumulate(
        &snark.protocol,
        loader,
        statements,
        &mut transcript,
        stretagy,
    )
    .map_err(|_| plonk::Error::Synthesis)?;
    Ok(())
}

pub struct Accumulation {
    g1: G1Affine,
    snarks: Vec<SnarkWitness<G1>>,
    instances: Vec<Fr>,
}

impl Accumulation {
    pub fn two_snark() -> Self {
        const K: u32 = 9;
        const N: usize = 1;

        let (params, snark1) = {
            let (params, pk, protocol, circuits) = halo2_prepare!(
                [kzg],
                K,
                N,
                None,
                StandardPlonk::<_>::rand(ChaCha20Rng::from_seed(Default::default()))
            );
            let snark = halo2_create_snark!(
                [kzg],
                &params,
                &pk,
                &protocol,
                &circuits,
                ProverSHPLONK<_>,
                VerifierSHPLONK<_>,
                BatchVerifier<_, _>,
                PoseidonTranscript<_, _, _, _>,
                PoseidonTranscript<_, _, _, _>,
                ChallengeScalar<_>
            );
            (params, snark)
        };
        let snark2 = {
            let (params, pk, protocol, circuits) = halo2_prepare!(
                [kzg],
                K,
                N,
                None,
                MainGateWithRange::<_>::rand(ChaCha20Rng::from_seed(Default::default()))
            );
            halo2_create_snark!(
                [kzg],
                &params,
                &pk,
                &protocol,
                &circuits,
                ProverSHPLONK<_>,
                VerifierSHPLONK<_>,
                BatchVerifier<_, _>,
                PoseidonTranscript<_, _, _, _>,
                PoseidonTranscript<_, _, _, _>,
                ChallengeScalar<_>
            )
        };

        let mut strategy = SameCurveAccumulation::<G1, NativeLoader>::default();
        halo2_native_accumulate!(
            [kzg],
            &snark1.protocol,
            snark1.statements.clone(),
            ShplonkAccumulationScheme,
            &mut PoseidonTranscript::<G1Affine, _, _, _>::init(snark1.proof.as_slice()),
            &mut strategy
        );
        halo2_native_accumulate!(
            [kzg],
            &snark2.protocol,
            snark2.statements.clone(),
            ShplonkAccumulationScheme,
            &mut PoseidonTranscript::<G1Affine, _, _, _>::init(snark2.proof.as_slice()),
            &mut strategy
        );

        let g1 = params.get_g()[0];
        let accumulator = strategy.finalize(g1.to_curve());
        let instances = [
            accumulator.0.to_affine().x,
            accumulator.0.to_affine().y,
            accumulator.1.to_affine().x,
            accumulator.1.to_affine().y,
        ]
        .map(fe_to_limbs::<_, _, LIMBS, BITS>)
        .concat();

        Self {
            g1,
            snarks: vec![snark1.into(), snark2.into()],
            instances,
        }
    }

    pub fn two_snark_with_accumulator() -> Self {
        const K: u32 = 21;
        const N: usize = 2;

        let accumulator_indices = (0..4 * LIMBS).map(|idx| (0, idx)).collect();
        let (params, pk, protocol, circuits) =
            halo2_prepare!([kzg], K, N, Some(accumulator_indices), Self::two_snark());
        let snark = halo2_create_snark!(
            [kzg],
            &params,
            &pk,
            &protocol,
            &circuits,
            ProverSHPLONK<_>,
            VerifierSHPLONK<_>,
            BatchVerifier<_, _>,
            PoseidonTranscript<_, _, _, _>,
            PoseidonTranscript<_, _, _, _>,
            ChallengeScalar<_>
        );

        let mut strategy = SameCurveAccumulation::<G1, NativeLoader>::default();
        halo2_native_accumulate!(
            [kzg],
            &snark.protocol,
            snark.statements.clone(),
            ShplonkAccumulationScheme,
            &mut PoseidonTranscript::<G1Affine, _, _, _>::init(snark.proof.as_slice()),
            &mut strategy
        );

        let g1 = params.get_g()[0];
        let accumulator = strategy.finalize(g1.to_curve());
        let instances = [
            accumulator.0.to_affine().x,
            accumulator.0.to_affine().y,
            accumulator.1.to_affine().x,
            accumulator.1.to_affine().y,
        ]
        .map(fe_to_limbs::<_, _, LIMBS, BITS>)
        .concat();

        Self {
            g1,
            snarks: vec![snark.into()],
            instances,
        }
    }

    pub fn instances(&self) -> Vec<Vec<Fr>> {
        vec![self.instances.clone()]
    }
}

impl Circuit<Fr> for Accumulation {
    type Config = MainGateWithRangeConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            g1: self.g1,
            snarks: self
                .snarks
                .iter()
                .map(SnarkWitness::without_witnesses)
                .collect(),
            instances: Vec::new(),
        }
    }

    fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
        MainGateWithRangeConfig::configure::<Fr>(
            meta,
            BaseFieldEccChip::<G1Affine>::rns().overflow_lengths(),
        )
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<Fr>,
    ) -> Result<(), plonk::Error> {
        config.load_table(&mut layouter, BITS / LIMBS)?;

        let (lhs, rhs) = layouter.assign_region(
            || "",
            |mut region| {
                let mut offset = 0;
                let ctx = RegionCtx::new(&mut region, &mut offset);

                let loader = Halo2Loader::<G1Affine>::new(config.ecc_config(), ctx);
                let mut stretagy = SameCurveAccumulation::default();
                for snark in self.snarks.iter() {
                    accumulate(&loader, &mut stretagy, snark)?;
                }
                let (lhs, rhs) = stretagy.finalize(self.g1);

                loader.print_row_metering();
                println!("Total: {}", offset);

                Ok((lhs, rhs))
            },
        )?;

        let ecc_chip = BaseFieldEccChip::<G1Affine>::new(config.ecc_config());
        ecc_chip.expose_public(layouter.namespace(|| ""), lhs, 0)?;
        ecc_chip.expose_public(layouter.namespace(|| ""), rhs, 2 * LIMBS)?;

        Ok(())
    }
}

#[test]
#[ignore = "cause it requires 64GB ram to run"]
fn test_shplonk_halo2_accumulation_two_snark() {
    const K: u32 = 21;
    const N: usize = 1;

    let accumulator_indices = (0..4 * LIMBS).map(|idx| (0, idx)).collect();
    let (params, pk, protocol, circuits) = halo2_prepare!(
        [kzg],
        K,
        N,
        Some(accumulator_indices),
        Accumulation::two_snark()
    );
    let snark = halo2_create_snark!(
        [kzg],
        &params,
        &pk,
        &protocol,
        &circuits,
        ProverSHPLONK<_>,
        VerifierSHPLONK<_>,
        BatchVerifier<_, _>,
        Blake2bWrite<_, _, _>,
        Blake2bRead<_, _, _>,
        Challenge255<_>
    );
    halo2_native_verify!(
        [kzg],
        params,
        &snark.protocol,
        snark.statements,
        ShplonkAccumulationScheme,
        &mut Blake2bRead::<_, G1Affine, _>::init(snark.proof.as_slice())
    );
}

#[test]
#[ignore = "cause it requires 128GB ram to run"]
fn test_shplonk_halo2_accumulation_two_snark_with_accumulator() {
    const K: u32 = 22;
    const N: usize = 1;

    let accumulator_indices = (0..4 * LIMBS).map(|idx| (0, idx)).collect();
    let (params, pk, protocol, circuits) = halo2_prepare!(
        [kzg],
        K,
        N,
        Some(accumulator_indices),
        Accumulation::two_snark_with_accumulator()
    );
    let snark = halo2_create_snark!(
        [kzg],
        &params,
        &pk,
        &protocol,
        &circuits,
        ProverSHPLONK<_>,
        VerifierSHPLONK<_>,
        BatchVerifier<_, _>,
        Blake2bWrite<_, _, _>,
        Blake2bRead<_, _, _>,
        Challenge255<_>
    );
    halo2_native_verify!(
        [kzg],
        params,
        &snark.protocol,
        snark.statements,
        ShplonkAccumulationScheme,
        &mut Blake2bRead::<_, G1Affine, _>::init(snark.proof.as_slice())
    );
}

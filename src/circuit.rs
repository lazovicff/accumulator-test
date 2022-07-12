use crate::{
    loader::halo2::Halo2Loader,
    protocol::native::Protocol,
    scheme::{self, AccumulationScheme, ShplonkAccumulationScheme},
    util::{fe_to_limbs, Curve, Group, PrimeCurveAffine},
};
use halo2_wrong::curves::bn256::{Fr, G1Affine, G1};
use halo2_wrong::halo2::{
    circuit::{floor_planner::V1, Layouter, Value},
    plonk,
    plonk::Circuit,
    poly::{
        commitment::ParamsProver,
        kzg::{
            multiopen::{ProverSHPLONK, VerifierSHPLONK},
            strategy::AccumulatorStrategy,
        },
    },
    transcript::{Blake2bRead, Blake2bWrite, Challenge255, TranscriptReadBuffer},
};
use halo2_wrong_ecc::BaseFieldEccChip;
use halo2_wrong_maingate::RegionCtx;
use halo2_wrong_transcript::NativeRepresentation;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use std::{rc::Rc, vec};
use crate::native::Snark;

const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 57;
pub const LIMBS: usize = 4;
pub const BITS: usize = 68;

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

pub struct Accumulation {
    g1: G1Affine,
    snarks: Vec<SnarkWitness<G1>>,
    instances: Vec<Fr>,
}

// impl Circuit<Fr> for Accumulation {
//     type Config = MainGateWithRangeConfig;
//     type FloorPlanner = V1;

//     fn without_witnesses(&self) -> Self {
//         Self {
//             g1: self.g1,
//             snarks: self
//                 .snarks
//                 .iter()
//                 .map(SnarkWitness::without_witnesses)
//                 .collect(),
//             instances: Vec::new(),
//         }
//     }

//     fn configure(meta: &mut plonk::ConstraintSystem<Fr>) -> Self::Config {
//         MainGateWithRangeConfig::configure::<Fr>(
//             meta,
//             BaseFieldEccChip::<G1Affine>::rns().overflow_lengths(),
// 			vec![BITS / LIMBS],
//         )
//     }

//     fn synthesize(
//         &self,
//         config: Self::Config,
//         mut layouter: impl Layouter<Fr>,
//     ) -> Result<(), plonk::Error> {
//         config.load_table(&mut layouter)?;

//         let (lhs, rhs) = layouter.assign_region(
//             || "",
//             |mut region| {
//                 let mut offset = 0;
//                 let ctx = RegionCtx::new(&mut region, &mut offset);

//                 let loader = Halo2Loader::<G1Affine>::new(config.ecc_config(), ctx);
//                 let mut stretagy = SameCurveAccumulation::default();
//                 for snark in self.snarks.iter() {
//                     let mut transcript = PoseidonTranscript::<_, Rc<Halo2Loader<G1Affine>>, _, _>::new(
// 						&loader,
// 						snark.proof.as_ref().map(|proof| proof.as_slice()),
// 					);
// 					let statements = snark
// 						.statements
// 						.iter()
// 						.map(|statements| {
// 							statements
// 								.iter()
// 								.map(|statement| loader.assign_scalar(*statement))
// 								.collect::<Vec<_>>()
// 						})
// 						.collect::<Vec<_>>();
// 					ShplonkAccumulationScheme::accumulate(
// 						&snark.protocol,
// 						&loader,
// 						statements,
// 						&mut transcript,
// 						&mut stretagy,
// 					)
// 					.map_err(|_| plonk::Error::Synthesis)?;
//                 }
//                 let (lhs, rhs) = stretagy.finalize(self.g1);

//                 loader.print_row_metering();
//                 println!("Total: {}", offset);

//                 Ok((lhs, rhs))
//             },
//         )?;

//         let ecc_chip = BaseFieldEccChip::<G1Affine>::new(config.ecc_config());
//         ecc_chip.expose_public(layouter.namespace(|| ""), lhs, 0)?;
//         ecc_chip.expose_public(layouter.namespace(|| ""), rhs, 2 * LIMBS)?;

//         Ok(())
//     }
// }
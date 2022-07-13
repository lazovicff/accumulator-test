use crate::{
    loader::halo2::Halo2Loader,
    protocol::Protocol,
    scheme::{AccumulationScheme, ShplonkAccumulationScheme},
    util::{Curve, Group},
};
use halo2_wrong::curves::pairing::Engine;
use halo2_wrong::halo2::{
	arithmetic::FieldExt,
    circuit::{floor_planner::V1, Layouter, Value},
    plonk::{Circuit, ConstraintSystem, Error},
};
use halo2_wrong_transcript::NativeRepresentation;
use halo2_wrong_ecc::BaseFieldEccChip;
use halo2_wrong_maingate::{RegionCtx, RangeInstructions};
use std::vec;
use crate::native::Snark;
use halo2_wrong_maingate::{MainGateConfig, MainGate, RangeConfig, RangeChip};
use halo2_wrong_ecc::EccConfig;
use crate::scheme::SameCurveAccumulation;
use crate::loader::halo2::PoseidonTranscript;

pub const LIMBS: usize = 4;
pub const BITS: usize = 68;

#[derive(Clone)]
pub struct AccumulatorConfig {
    main_gate_config: MainGateConfig,
    range_config: RangeConfig,
}

impl AccumulatorConfig {
    fn ecc_config(&self) -> EccConfig {
        EccConfig::new(self.range_config.clone(), self.main_gate_config.clone())
    }

    fn load_table<F: FieldExt>(&self, layouter: &mut impl Layouter<F>) -> Result<(), Error> {
        let range_chip = RangeChip::<F>::new(self.range_config.clone());
        range_chip.load_composition_tables(layouter)?;
		range_chip.load_overflow_tables(layouter)?;
        Ok(())
    }
}

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

pub struct Accumulator<E: Engine> {
    g1: E::G1Affine,
    snarks: Vec<SnarkWitness<E::G1>>,
}

impl<E: Engine> Circuit<E::Scalar> for Accumulator<E> {
    type Config = AccumulatorConfig;
    type FloorPlanner = V1;

    fn without_witnesses(&self) -> Self {
        Self {
            g1: self.g1,
            snarks: self
                .snarks
                .iter()
                .map(SnarkWitness::without_witnesses)
                .collect(),
        }
    }

    fn configure(meta: &mut ConstraintSystem<E::Scalar>) -> Self::Config {
		let composition_bits = BaseFieldEccChip::<E::G1Affine, LIMBS, BITS>::rns().overflow_lengths();
		let overflow_bits = vec![BITS / LIMBS];
		let main_gate_config = MainGate::<E::Scalar>::configure(meta);
        let range_config =
            RangeChip::<E::Scalar>::configure(meta, &main_gate_config, composition_bits, overflow_bits);
		AccumulatorConfig {
            main_gate_config,
            range_config,
        }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<E::Scalar>,
    ) -> Result<(), Error> {
        config.load_table(&mut layouter)?;

        let (lhs, rhs) = layouter.assign_region(
            || "",
            |mut region| {
                let mut offset = 0;
                let ctx = RegionCtx::new(&mut region, &mut offset);

                let loader = Halo2Loader::<E::G1Affine, LIMBS, BITS>::new(config.ecc_config(), ctx);
                let mut stretagy = SameCurveAccumulation::default();
                for snark in self.snarks.iter() {
                    let mut transcript = PoseidonTranscript::<E::G1Affine, _, NativeRepresentation, LIMBS, BITS>::new(
						&loader,
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
						&loader,
						statements,
						&mut transcript,
						&mut stretagy,
					)
					.map_err(|_| Error::Synthesis)?;
                }
                let (lhs, rhs) = stretagy.finalize(self.g1);

                Ok((lhs, rhs))
            },
        )?;

        let ecc_chip = BaseFieldEccChip::<E::G1Affine, LIMBS, BITS>::new(config.ecc_config());
        ecc_chip.expose_public(layouter.namespace(|| ""), lhs, 0)?;
        ecc_chip.expose_public(layouter.namespace(|| ""), rhs, 2 * LIMBS)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
	#[test]
	fn should_accumulate_two_proofs() {
		
	}
}
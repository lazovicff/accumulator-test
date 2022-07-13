use crate::{
    loader::{
        halo2::loader::{EcPoint, Halo2Loader, Scalar, Value},
    },
    util::{PrimeField, Transcript, TranscriptRead},
    Error,
};
use halo2_wrong::curves::CurveAffine;
use halo2_wrong::halo2::circuit;
use halo2_wrong_transcript::{PointRepresentation, TranscriptChip};
use poseidon::Spec;
use std::{
    io::Read,
    marker::PhantomData,
    rc::Rc,
};

const T: usize = 5;
const RATE: usize = 4;
const R_F: usize = 8;
const R_P: usize = 57;

pub struct PoseidonTranscript<
    'a,
    'b,
    C: CurveAffine,
	R: Read,
	E: PointRepresentation<C, LIMBS, BITS>,
    const LIMBS: usize,
    const BITS: usize,
> {
    loader: Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>,
    stream: circuit::Value<R>,
    buf: TranscriptChip<E, C, LIMBS, BITS, T, RATE>,
    _marker: PhantomData<(C, E)>,
}

impl<
        'a,
        'b,
        C: CurveAffine,
        R: Read,
        E: PointRepresentation<C, LIMBS, BITS>,
        const LIMBS: usize,
        const BITS: usize,
    >
    PoseidonTranscript<
		'a,
		'b,
        C,
		R,
		E,
        LIMBS,
        BITS,
    >
{
    pub fn new(
        loader: &Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>,
        stream: circuit::Value<R>,
    ) -> Self {
        let transcript_chip = TranscriptChip::new(
            &mut loader.ctx_mut(),
            &Spec::new(R_F, R_P),
            loader.ecc_chip().clone(),
        )
        .unwrap();
        Self {
            loader: loader.clone(),
            stream,
            buf: transcript_chip,
            _marker: PhantomData,
        }
    }
}

impl<
        'a,
        'b,
        C: CurveAffine,
        R: Read,
        E: PointRepresentation<C, LIMBS, BITS>,
        const LIMBS: usize,
        const BITS: usize,
    > Transcript<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>>
    for PoseidonTranscript<
		'a,
		'b,
		C,
		R,
		E,
		LIMBS,
		BITS,
    >
{
    fn squeeze_challenge(&mut self) -> Scalar<'a, 'b, C, LIMBS, BITS> {
        let assigned = self.buf.squeeze(&mut self.loader.ctx_mut()).unwrap();
        self.loader.scalar(Value::Assigned(assigned))
    }

    fn common_scalar(&mut self, scalar: &Scalar<'a, 'b, C, LIMBS, BITS>) -> Result<(), Error> {
        self.buf.write_scalar(&scalar.assigned());
        Ok(())
    }

    fn common_ec_point(&mut self, ec_point: &EcPoint<'a, 'b, C, LIMBS, BITS>) -> Result<(), Error> {
        self.buf
            .write_point(&mut self.loader.ctx_mut(), &ec_point.assigned())
            .unwrap();
        Ok(())
    }
}

impl<
        'a,
        'b,
        C: CurveAffine,
        R: Read,
        E: PointRepresentation<C, LIMBS, BITS>,
        const LIMBS: usize,
        const BITS: usize,
    > TranscriptRead<C::CurveExt, Rc<Halo2Loader<'a, 'b, C, LIMBS, BITS>>>
    for PoseidonTranscript<
		'a,
		'b,
		C,
		R,
		E,
		LIMBS,
		BITS,
    >
{
    fn read_scalar(&mut self) -> Result<Scalar<'a, 'b, C, LIMBS, BITS>, Error> {
        let scalar = self.stream.as_mut().and_then(|stream| {
            let mut data = <C::Scalar as PrimeField>::Repr::default();
            if stream.read_exact(data.as_mut()).is_err() {
                return circuit::Value::unknown();
            }
            Option::<C::Scalar>::from(C::Scalar::from_repr(data))
                .map(circuit::Value::known)
                .unwrap_or_else(circuit::Value::unknown)
        });
        let scalar = self.loader.assign_scalar(scalar);
        self.common_scalar(&scalar)?;
        Ok(scalar)
    }

    fn read_ec_point(&mut self) -> Result<EcPoint<'a, 'b, C, LIMBS, BITS>, Error> {
        let ec_point = self.stream.as_mut().and_then(|stream| {
            let mut compressed = C::Repr::default();
            if stream.read_exact(compressed.as_mut()).is_err() {
                return circuit::Value::unknown();
            }
            Option::<C>::from(C::from_bytes(&compressed))
                .map(circuit::Value::known)
                .unwrap_or_else(circuit::Value::unknown)
        });
        let ec_point = self.loader.assign_ec_point(ec_point);
        self.common_ec_point(&ec_point)?;
        Ok(ec_point)
    }
}
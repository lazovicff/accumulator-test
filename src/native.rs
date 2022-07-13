use crate::util::{Curve, Group};
use crate::protocol::Protocol;

pub struct Snark<C: Curve> {
    pub(crate) protocol: Protocol<C>,
    pub(crate) statements: Vec<Vec<<C as Group>::Scalar>>,
    pub(crate) proof: Vec<u8>,
}

impl<C: Curve> Snark<C> {
    pub fn new(
        protocol: Protocol<C>,
        statements: Vec<Vec<<C as Group>::Scalar>>,
        proof: Vec<u8>,
    ) -> Self {
        Snark {
            protocol,
            statements,
            proof,
        }
    }
}
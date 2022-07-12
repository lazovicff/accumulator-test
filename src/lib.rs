#![feature(int_log)]
#![feature(int_roundings)]
#![allow(clippy::type_complexity)]
#![allow(clippy::too_many_arguments)]
#![allow(clippy::upper_case_acronyms)]

pub mod loader;
pub mod protocol;
pub mod scheme;
pub mod circuit;
pub mod native;
pub mod util;

#[derive(Clone, Debug)]
pub enum Error {
    InvalidInstances,
    MissingQuery(util::Query),
    MissingChallenge(usize),
    Transcript(std::io::ErrorKind, String),
}

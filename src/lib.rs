pub mod proto {
    #![allow(clippy::derive_partial_eq_without_eq)]
    tonic::include_proto!("mith.v1");
}

pub mod database;
pub mod error;
pub mod util;

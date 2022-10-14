use std::fmt;

#[derive(Debug, Clone)]
pub struct ProxyCheckError;

impl fmt::Display for ProxyCheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "received error from proxycheck api")
    }
}

#[derive(Debug, Clone)]
pub struct NewPlayerError;

impl fmt::Display for NewPlayerError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "error while creating new player instance")
    }
}

#[derive(Debug, Clone)]
pub struct UpdatePasswordError;

impl fmt::Display for UpdatePasswordError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "error while updating player password")
    }
}

pub enum Error {
    Unspecified,
    NotFound,
    AlreadyExists,
    UsingVpn,
    InvalidPassword,
    InvalidUsername,
}

use std::fmt;

#[derive(Debug, Clone)]
pub struct ProxyCheckError;

impl fmt::Display for ProxyCheckError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "received error from proxycheck api")
    }
}

pub enum Error {
    Unspecified,
    NotFound,
    AlreadyExists,
    UsingVpn,
    InvalidPassword,
}

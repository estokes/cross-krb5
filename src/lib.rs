use anyhow::Result;
use bytes::BytesMut;
use std::{ops::Deref, time::Duration};

pub trait K5ClientCtx {
    type Buf: Deref<Target = [u8]> + Send + Sync;

    fn step(&self, token: Option<&[u8]>) -> Result<Option<Self::Buf>>;
    fn wrap(&self, encrypt: bool, msg: &[u8]) -> Result<Self::Buf>;
    fn wrap_iov(
        &self,
        encrypt: bool,
        header: &mut BytesMut,
        data: &mut BytesMut,
        padding: &mut BytesMut,
        trailer: &mut BytesMut,
    ) -> Result<()>;
    fn unwrap(&self, msg: &[u8]) -> Result<Self::Buf>;
    fn unwrap_iov(&self, len: usize, msg: &mut BytesMut) -> Result<BytesMut>;
    fn ttl(&self) -> Result<Duration>;
}

pub trait K5ServerCtx: K5ClientCtx {
    fn client(&self) -> Result<String>;
}

#[cfg(unix)]
pub mod unix;

#[cfg(unix)]
pub use crate::unix::{ClientCtx, ServerCtx};

#[cfg(windows)]
pub mod windows;

#[cfg(windows)]
pub use crate::windows::{ClientCtx, ServerCtx};

//! # Cross Platform Kerberos 5 Interface
//!
//! cross-krb5 is a simplified and safe interface for basic Kerberos 5
//! services on Windows and Unix. It provides most of the flexibility
//! of using gssapi and sspi directly, but with the reduced api
//! complexity that comes from specifically targeting only the
//! Kerberos 5 mechanism.
//!
//! As well as providing a uniform API, services using cross-krb5
//! should interoperate across all the supported OSes transparently,
//! and should interoperate with other services assuming they are not
//! platform specific.
//!
//! # Example
//! ```no_run
//! # use anyhow::Result;
//! # fn run(spn: &str) -> Result<()> {
//! use cross_krb5::{
//!     ClientCtx,
//!     ServerCtx,
//!     K5Ctx,
//!     K5ServerCtx,
//!     InitiateFlags,
//!     AcceptFlags
//! };
//!
//! // make a pending context and a token to connect to `service/host@REALM`
//! let (pending, token) = ClientCtx::initiate(
//!      InitiateFlags::empty(),
//!      None,
//!      "service/host@REALM",
//!      None
//! )?;
//!
//! // accept the client's token for `service/host@REALM`. The token from the client
//! // is accepted, and, if valid, the server end of the context and a token
//! // for the client will be created.
//! let (mut server, token) = ServerCtx::accept(
//!      AcceptFlags::empty(),
//!      Some("service/host@REALM"),
//!      &*token
//! )?;
//!
//! // use the server supplied token to finish initializing the pending client context.
//! // Now encrypted communication between the two contexts is possible, and mutual
//! // authentication has succeeded.
//! let mut client = pending.finish(&*token)?;
//!
//! // send secret messages
//! let secret_msg = client.wrap(true, b"super secret message")?;
//! println!("{}", String::from_utf8_lossy(&server.unwrap(&*secret_msg)?));
//!
//! // ... profit!
//!# Ok(())
//!# }
//! ```

use anyhow::Result;
use bytes::{Buf, BytesMut};
use std::{ops::Deref, time::Duration};
#[macro_use]
extern crate bitflags;

pub trait K5Ctx {
    type Buffer: Deref<Target = [u8]> + Send + Sync;
    type IOVBuffer: Buf + Send + Sync;

    /// Wrap the specified message for sending to the other side. If
    /// `encrypt` is true then the contents will be encrypted. Even if
    /// `encrypt` is false the integrity of the contents are
    /// protected, if the message is altered in transit the other side
    /// will know.
    fn wrap(&mut self, encrypt: bool, msg: &[u8]) -> Result<Self::Buffer>;

    /// Wrap data in place using the underlying wrap_iov facility. If
    /// `encrypt` is true then the contents of `data` will be
    /// encrypted in place. The returned buffer is NOT contiguous, and
    /// as such you must use some kind of `writev` implementation to
    /// properly send it. You can use tokio's `write_buf` directly, or
    /// you can extract the iovecs for a direct call to `writev` using
    /// `bytes::Buf::chunks_vectored`.
    ///
    /// If feature `iov` isn't enabled (it's in the default set)
    /// then the underlying functionaly will be emulated, and there
    /// will be no performance gain. `iov` is currently not
    /// available on Mac OS, and compilation will fail if you try to
    /// enable it. On OSes where it is supported using
    /// wrap_iov/unwrap_iov is generally in the neighborhood of 2x to
    /// 3x faster than wrap/unwrap.
    fn wrap_iov(&mut self, encrypt: bool, msg: BytesMut) -> Result<Self::IOVBuffer>;

    /// Unwrap the specified message returning it's decrypted and
    /// verified contents
    fn unwrap(&mut self, msg: &[u8]) -> Result<Self::Buffer>;

    /// Unwrap in place the message at the beginning of the specified
    /// `BytesMut` and then split it off and return it. This won't
    /// copy or allocate, it just looks that way because the bytes
    /// crate is awesome.
    fn unwrap_iov(&mut self, len: usize, msg: &mut BytesMut) -> Result<BytesMut>;

    /// Return the remaining time this session has to live
    fn ttl(&mut self) -> Result<Duration>;
}

pub trait K5ServerCtx: K5Ctx {
    /// Return the user principal name of the client context
    /// associated with this server context.
    fn client(&mut self) -> Result<String>;
}

#[cfg(unix)]
mod unix;

#[cfg(unix)]
use crate::unix::{
    ClientCtx as ClientCtxImpl, PendingClientCtx as PendingClientCtxImpl,
    PendingServerCtx as PendingServerCtxImpl, ServerCtx as ServerCtxImpl,
};

#[cfg(windows)]
mod windows;

#[cfg(windows)]
use crate::windows::{
    ClientCtx as ClientCtxImpl, PendingClientCtx as PendingClientCtxImpl,
    PendingServerCtx as PendingServerCtxImpl, ServerCtx as ServerCtxImpl,
};

pub enum OrContinue<C, T> {
    Finished(C),
    Continue(T),
}

/// a half initialized client context
pub struct PendingClientCtx(PendingClientCtxImpl);

impl PendingClientCtx {
    /// Feed the server provided token to the underling implementation,
    /// if the negotiation is complete then return the established context and optionally a token,
    /// otherwise, return another token to pass to the server.
    pub fn step(
        self,
        token: &[u8],
    ) -> Result<
        OrContinue<
            (ClientCtx, Option<impl Deref<Target = [u8]>>),
            (PendingClientCtx, impl Deref<Target = [u8]>),
        >,
    > {
        Ok(match self.0.step(token)? {
            OrContinue::Finished((ctx, tok)) => {
                OrContinue::Finished((ClientCtx(ctx), tok))
            }
            OrContinue::Continue((ctx, tok)) => {
                OrContinue::Continue((PendingClientCtx(ctx), tok))
            }
        })
    }
}

bitflags! {
    pub struct InitiateFlags: u32 {
        /// Windows only, use the sspi negotiate package instead of
        /// the Kerberos package. Some Windows servers expect these
        /// tokens instead of normal gssapi compatible tokens.
        const NEGOTIATE_TOKEN = 0x1;
    }
}

/// A Kerberos client context
#[derive(Debug)]
pub struct ClientCtx(ClientCtxImpl);

impl ClientCtx {
    /// Initiate a client context to `target_principal`. If
    /// `principal` is `None` then the credentials of the user running
    /// current process will be used. `target_principal` must be the
    /// service principal name of the service you intend to
    /// communicate with. This should be an spn as described by
    /// GSSAPI, e.g. `service/host@REALM`. If present, `channel_bindings` is
    /// a service-specific channel binding token which will be part
    /// of the initial communication with the server.
    ///
    /// On success a `PendingClientCtx` and a token to be sent to the
    /// server will be returned. The server will accept the client
    /// token, and, if valid, will return a token of it's own, which
    /// must be passed to the `PendingClientCtx::finish` method to
    /// complete the initialization.
    pub fn initiate(
        flags: InitiateFlags,
        principal: Option<&str>,
        target_principal: &str,
        channel_bindings: Option<&[u8]>,
    ) -> Result<(PendingClientCtx, impl Deref<Target = [u8]>)> {
        let (pending, token) = ClientCtxImpl::initiate(
            flags,
            principal,
            target_principal,
            channel_bindings,
        )?;
        Ok((PendingClientCtx(pending), token))
    }
}

impl K5Ctx for ClientCtx {
    type Buffer = <ClientCtxImpl as K5Ctx>::Buffer;
    type IOVBuffer = <ClientCtxImpl as K5Ctx>::IOVBuffer;

    fn wrap(&mut self, encrypt: bool, msg: &[u8]) -> Result<Self::Buffer> {
        K5Ctx::wrap(&mut self.0, encrypt, msg)
    }

    fn wrap_iov(&mut self, encrypt: bool, msg: BytesMut) -> Result<Self::IOVBuffer> {
        K5Ctx::wrap_iov(&mut self.0, encrypt, msg)
    }

    fn unwrap(&mut self, msg: &[u8]) -> Result<Self::Buffer> {
        K5Ctx::unwrap(&mut self.0, msg)
    }

    fn unwrap_iov(&mut self, len: usize, msg: &mut BytesMut) -> Result<BytesMut> {
        K5Ctx::unwrap_iov(&mut self.0, len, msg)
    }

    fn ttl(&mut self) -> Result<Duration> {
        K5Ctx::ttl(&mut self.0)
    }
}

bitflags! {
    pub struct AcceptFlags: u32 {
        /// Windows only, use the sspi negotiate package instead of
        /// the Kerberos package. Some Windows clients generate these
        /// tokens instead of normal gssapi compatible tokens. This
        /// likely won't be able to parse gssapi tokens, so only use
        /// this if you know the client will be on windows sending
        /// negotiate tokens.
        const NEGOTIATE_TOKEN = 0x1;
    }
}

pub struct PendingServerCtx(PendingServerCtxImpl);

impl PendingServerCtx {
    pub fn step(
        self,
        token: &[u8],
    ) -> Result<
        OrContinue<
            (ServerCtx, Option<impl Deref<Target = [u8]>>),
            (PendingServerCtx, impl Deref<Target = [u8]>),
        >,
    > {
        Ok(match self.0.step(token)? {
            OrContinue::Finished((ctx, tok)) => {
                OrContinue::Finished((ServerCtx(ctx), tok))
            }
            OrContinue::Continue((ctx, tok)) => {
                OrContinue::Continue((PendingServerCtx(ctx), tok))
            }
        })
    }
}

/// A Kerberos server context
#[derive(Debug)]
pub struct ServerCtx(ServerCtxImpl);

impl ServerCtx {
    /// Accept a client request for `principal`. `principal` should be
    /// the service principal name assigned to the service the client
    /// is requesting.  If it is left as `None` it will use the user
    /// running the current process. `token` should be the token
    /// received from the client that initiated the request for
    /// service. If the token sent by the client is valid, then the
    /// context and a token to send back to the client will be
    /// returned.
    pub fn create(
        flags: AcceptFlags,
        principal: Option<&str>,
    ) -> Result<PendingServerCtx> {
        Ok(PendingServerCtx(ServerCtxImpl::create(flags, principal)?))
    }
}

impl K5Ctx for ServerCtx {
    type Buffer = <ServerCtxImpl as K5Ctx>::Buffer;
    type IOVBuffer = <ServerCtxImpl as K5Ctx>::IOVBuffer;

    fn wrap(&mut self, encrypt: bool, msg: &[u8]) -> Result<Self::Buffer> {
        K5Ctx::wrap(&mut self.0, encrypt, msg)
    }

    fn wrap_iov(&mut self, encrypt: bool, msg: BytesMut) -> Result<Self::IOVBuffer> {
        K5Ctx::wrap_iov(&mut self.0, encrypt, msg)
    }

    fn unwrap(&mut self, msg: &[u8]) -> Result<Self::Buffer> {
        K5Ctx::unwrap(&mut self.0, msg)
    }

    fn unwrap_iov(&mut self, len: usize, msg: &mut BytesMut) -> Result<BytesMut> {
        K5Ctx::unwrap_iov(&mut self.0, len, msg)
    }

    fn ttl(&mut self) -> Result<Duration> {
        K5Ctx::ttl(&mut self.0)
    }
}

impl K5ServerCtx for ServerCtx {
    fn client(&mut self) -> Result<String> {
        K5ServerCtx::client(&mut self.0)
    }
}

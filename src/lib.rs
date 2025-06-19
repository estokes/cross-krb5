//! # Cross Platform Kerberos 5 Interface
//!
//! cross-krb5 is a safe interface for Kerberos 5 services on Windows
//! and Unix. It provides most of the flexibility of using gssapi and
//! sspi directly with a unified cross platform api.
//!
//! As well as providing a uniform API, services using cross-krb5
//! should interoperate across all the supported OSes transparently,
//! and should interoperate with other services assuming they are not
//! platform specific.
//!
//! # Example
//! ```no_run
//! use bytes::Bytes;
//! use cross_krb5::{AcceptFlags, ClientCtx, InitiateFlags, K5Ctx, Step, ServerCtx};
//! use std::{env::args, process::exit, sync::mpsc, thread};
//!
//! enum Msg {
//!     Token(Bytes),
//!     Msg(Bytes),
//! }
//!
//! fn server(spn: String, input: mpsc::Receiver<Msg>, output: mpsc::Sender<Msg>) {
//!     let mut server = ServerCtx::new(AcceptFlags::empty(), Some(&spn)).expect("new");
//!     let mut server = loop {
//!         let token = match input.recv().expect("expected data") {
//!             Msg::Msg(_) => panic!("server not finished initializing"),
//!             Msg::Token(t) => t,
//!         };
//!         match server.step(&*token).expect("step") {
//!             Step::Finished((ctx, token)) => {
//!                 if let Some(token) = token {
//!                     output.send(Msg::Token(Bytes::copy_from_slice(&*token))).expect("send");
//!                 }
//!                 break ctx
//!             },
//!             Step::Continue((ctx, token)) => {
//!                 output.send(Msg::Token(Bytes::copy_from_slice(&*token))).expect("send");
//!                 server = ctx;
//!             }
//!         }
//!     };
//!     match input.recv().expect("expected data msg") {
//!         Msg::Token(_) => panic!("unexpected extra token"),
//!         Msg::Msg(secret_msg) => println!(
//!             "{}",
//!             String::from_utf8_lossy(&server.unwrap(&*secret_msg).expect("unwrap"))
//!         ),
//!     }
//! }
//!
//! fn client(spn: &str, input: mpsc::Receiver<Msg>, output: mpsc::Sender<Msg>) {
//!     let (mut client, token) =
//!         ClientCtx::new(InitiateFlags::empty(), None, spn, None).expect("new");
//!     output.send(Msg::Token(Bytes::copy_from_slice(&*token))).expect("send");
//!     let mut client = loop {
//!         let token = match input.recv().expect("expected data") {
//!             Msg::Msg(_) => panic!("client not finished initializing"),
//!             Msg::Token(t) => t,
//!         };
//!         match client.step(&*token).expect("step") {
//!             Step::Finished((ctx, token)) => {
//!                 if let Some(token) = token {
//!                     output.send(Msg::Token(Bytes::copy_from_slice(&*token))).expect("send");
//!                 }
//!                 break ctx
//!             },
//!             Step::Continue((ctx, token)) => {
//!                 output.send(Msg::Token(Bytes::copy_from_slice(&*token))).expect("send");
//!                 client = ctx;
//!             }
//!         }
//!     };
//!     let msg = client.wrap(true, b"super secret message").expect("wrap");
//!     output.send(Msg::Msg(Bytes::copy_from_slice(&*msg))).expect("send");
//! }
//!
//! fn main() {
//!     let args = args().collect::<Vec<_>>();
//!     if args.len() != 2 {
//!         println!("usage: {}: <service/host@REALM>", args[0]);
//!         exit(1);
//!     }
//!     let spn = String::from(&args[1]);
//!     let (server_snd, server_recv) = mpsc::channel();
//!     let (client_snd, client_recv) = mpsc::channel();
//!     thread::spawn(move || server(spn, server_recv, client_snd));
//!     client(&args[1], client_recv, server_snd);
//! }
//! ```

#[macro_use]
extern crate bitflags;
use anyhow::Result;
use bytes::{Buf, BytesMut};
use std::{ops::Deref, time::Duration};
#[cfg(windows)]
use ::windows::Win32::Security::Credentials::SecHandle;

pub trait K5Cred: Sized {
    fn server_acquire(
        _flags: AcceptFlags,
        principal: Option<&str>,
    ) -> Result<Self>;

    fn client_acquire(
        _flags: InitiateFlags,
        principal: Option<&str>,
    ) -> Result<Self>;
}

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
    ClientCtx as ClientCtxImpl, Cred as CredImpl,
    PendingClientCtx as PendingClientCtxImpl, PendingServerCtx as PendingServerCtxImpl,
    ServerCtx as ServerCtxImpl
};

#[cfg(windows)]
mod windows;

#[cfg(windows)]
use crate::windows::{
    ClientCtx as ClientCtxImpl, PendingClientCtx as PendingClientCtxImpl,
    PendingServerCtx as PendingServerCtxImpl, ServerCtx as ServerCtxImpl,
    Cred as CredImpl
};

pub enum Step<C, T> {
    Finished(C),
    Continue(T),
}

#[derive(Debug)]
pub struct Cred(CredImpl);
impl K5Cred for Cred {
    fn server_acquire(flags: AcceptFlags, principal: Option<&str>) -> Result<Cred> {
        CredImpl::server_acquire(flags, principal).map(Cred)
    }
    fn client_acquire(flags: InitiateFlags, principal: Option<&str>) -> Result<Cred> {
        CredImpl::client_acquire(flags, principal).map(Cred)
    }
}

impl From<CredImpl> for Cred {
    fn from(cred: CredImpl) -> Self {
        Cred(cred)
    }
}

#[cfg(unix)]
impl From<libgssapi::credential::Cred> for Cred {
    fn from(value: libgssapi::credential::Cred) -> Self {
        Cred(CredImpl::from(value))
    }
}

#[cfg(unix)]
impl Into<libgssapi::credential::Cred> for Cred {
    fn into(self) -> libgssapi::credential::Cred {
        self.0.into()
    }
}

#[cfg(windows)]
impl From<SecHandle> for Cred {
    fn from(value: SecHandle) -> Self {
        Cred(CredImpl::from(value))
    }
}

#[cfg(windows)]
impl Into<SecHandle> for Cred {
    fn into(self) -> SecHandle {
        self.0.into()
    }
}

/// a partly initialized client context
pub struct PendingClientCtx(PendingClientCtxImpl);

impl PendingClientCtx {
    /// Feed the server provided token to the client context,
    /// performing one step of the initialization. If the
    /// initialization is complete then return the established context
    /// and optionally a final token that must be sent to the server,
    /// otherwise return the pending context and another token to pass
    /// to the server.
    pub fn step(
        self,
        token: &[u8],
    ) -> Result<
        Step<
            (ClientCtx, Option<impl Deref<Target = [u8]>>),
            (PendingClientCtx, impl Deref<Target = [u8]>),
        >,
    > {
        Ok(match self.0.step(token)? {
            Step::Finished((ctx, tok)) => {
                Step::Finished((ClientCtx(ctx), tok))
            }
            Step::Continue((ctx, tok)) => {
                Step::Continue((PendingClientCtx(ctx), tok))
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
    /// create a new client context for speaking to
    /// `target_principal`. If `principal` is `None` then the
    /// credentials of the user running current process will be
    /// used. `target_principal` must be the service principal name of
    /// the service you intend to communicate with. This should be an
    /// spn as described by GSSAPI, e.g. `service/host@REALM`. If
    /// present, `channel_bindings` is a service-specific channel
    /// binding token which will be part of the initial communication
    /// with the server.
    ///
    /// On success a `PendingClientCtx` and a token to be sent to the
    /// server will be returned. The server and client may generate
    /// multiple additional tokens, which must be passed to the their
    /// respective `step` methods until the initialization is
    /// complete.
    pub fn new(
        flags: InitiateFlags,
        principal: Option<&str>,
        target_principal: &str,
        channel_bindings: Option<&[u8]>,
    ) -> Result<(PendingClientCtx, impl Deref<Target = [u8]>)> {
        let (pending, token) =
            ClientCtxImpl::new(flags, principal, target_principal, channel_bindings)?;
        Ok((PendingClientCtx(pending), token))
    }

    pub fn new_with_cred(
        cred: Cred,
        target_principal: &str,
        channel_bindings: Option<&[u8]>
    ) -> Result<(PendingClientCtx, impl Deref<Target=[u8]>)> {
        let (pending, token) =
            ClientCtxImpl::new_with_cred(cred.0, target_principal, channel_bindings)?;
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
        Step<
            (ServerCtx, Option<impl Deref<Target = [u8]>>),
            (PendingServerCtx, impl Deref<Target = [u8]>),
        >,
    > {
        Ok(match self.0.step(token)? {
            Step::Finished((ctx, tok)) => {
                Step::Finished((ServerCtx(ctx), tok))
            }
            Step::Continue((ctx, tok)) => {
                Step::Continue((PendingServerCtx(ctx), tok))
            }
        })
    }
}

/// A Kerberos server context
#[derive(Debug)]
pub struct ServerCtx(ServerCtxImpl);

impl ServerCtx {
    /// Create a new server context for `principal`, which should be
    /// the service principal name assigned to the service the client
    /// will be requesting. If it is left as `None` it will use the
    /// user running the current process. The returned pending context
    /// must be initiaized by exchanging one or more tokens with the
    /// client before it can be used.
    pub fn new(flags: AcceptFlags, principal: Option<&str>) -> Result<PendingServerCtx> {
        Ok(PendingServerCtx(ServerCtxImpl::new(flags, principal)?))
    }

    pub fn new_with_cred(cred: Cred) -> Result<PendingServerCtx> {
        Ok(PendingServerCtx(ServerCtxImpl::new_with_cred(cred.0)?))
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

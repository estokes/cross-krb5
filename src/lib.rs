//! Cross platform Kerberos 5
//!
//! cross-krb5 is a single API for basic Kerberos 5 services on Windows, Mac OS,
//! Linux, and Unix like OSes. It provides most of what gssapi and sspi provide for
//! kerberos 5 mechanisms, namely mutual authentication, integrity, and encryption.
//!
//! As well as providing a uniform API, services using cross-krb5 should interoperate
//! across all the supported OSes transparantly, and should interoperate with other
//! services assuming they are not platform specific.
//!
//! # Example
//! ```no_run
//! # use anyhow::Result;
//! use cross_krb5::{ClientCtx, ServerCtx, K5Ctx, K5ServerCtx};
//!
//!# fn run(spn: &str) -> Result<()> {
//! // setup the server context using the service principal name
//! let server = ServerCtx::new(Some(spn))?;
//! // The current user will request a service ticket for the spn
//! let client = ClientCtx::new(None, spn)?;
//! let mut server_tok: Option<<ClientCtx as K5Ctx>::Buf> = None;
//! loop {
//!     // the client and server exchange tokens until one of them is done
//!     match client.step(server_tok.as_ref().map(|b| &**b))? {
//!         None => break,
//!         Some(client_tok) => match server.step(Some(&*client_tok))? {
//!             None => break,
//!             Some(tok) => {
//!                 server_tok = Some(tok);
//!             }
//!         },
//!     }
//! }
//! // now that the sesion is established the client and server can
//! // encrypt messages to each other.
//! let secret_msg = client.wrap(true, b"super secret message")?;
//! println!("{}", String::from_utf8_lossy(&server.unwrap(&*secret_msg)?));
//!# Ok(())
//!# }
//! ```

use anyhow::Result;
use bytes::BytesMut;
use std::{ops::Deref, time::Duration};

pub trait K5Ctx {
    /// The type of buffer that will be returned by the context
    type Buf: Deref<Target = [u8]> + Send + Sync;

    /// perform 1 step of initialization. `token` is the token you received from the other
    /// side, or `None` if you didn't receive one. If initialization is finished then `step`
    /// will return `Ok(None)`, and at that point the context is ready to use.
    /// If `step` returns `Ok(Some(buf))` then initialization isn't finished and you are
    /// expected to send the contents of that buffer to the other side in order to finish it.
    /// This may go on for several rounds of back and forth.
    fn step(&self, token: Option<&[u8]>) -> Result<Option<Self::Buf>>;

    /// Wrap the specified message for sending to the other side. If `encrypt`
    /// is true then the contents will be encrypted. Even if `encrypt` is false
    /// the integrity of the contents are protected, if the message is altered in
    /// transit the other side will know.
    fn wrap(&self, encrypt: bool, msg: &[u8]) -> Result<Self::Buf>;

    /// Wrap data in place using the underlying wrap_iov facility. If `encrypt` is true
    /// then the contents of `data` will be encrypted in place. `header`, `padding`, and `trailer`
    /// may be references to empty newly created `BytesMut` structures, they will be resized as needed,
    /// and can be reused for subsuquent calls in order to avoid allocation. In order to send the message
    /// produced by `wrap_iov` you should send in order the header, data, padding, and trailer.
    /// # Examples
    /// ```no_run
    /// use bytes::{BytesMut, Buf};
    /// use cross_krb5::{ClientCtx, K5Ctx};
    /// # let ctx = unsafe { std::mem::zeroed::<ClientCtx>() };
    /// let mut header = BytesMut::new();
    /// let mut data = BytesMut::from(b"hello world".as_slice());
    /// let mut padding = BytesMut::new();
    /// let mut trailer = BytesMut::new();
    ///
    /// ctx.wrap_iov(true, &mut header, &mut data, &mut padding, &mut trailer)
    ///     .expect("failed to encrypt");
    /// // use the bytes api to chain together the token without any allocation or copying
    /// let mut buf = header.split().chain(data.chain(padding.split().chain(trailer.split())));
    /// // then use your prefered `writev` implementation. tokio `write_buf` is quite convenient
    /// ```
    fn wrap_iov(
        &self,
        encrypt: bool,
        header: &mut BytesMut,
        data: &mut BytesMut,
        padding: &mut BytesMut,
        trailer: &mut BytesMut,
    ) -> Result<()>;

    /// Unwrap the specified message returning it's decrypted and verified contents
    fn unwrap(&self, msg: &[u8]) -> Result<Self::Buf>;

    /// Unwrap in place the message at the beginning of the specified `BytesMut` and then split it off
    /// and return it. This won't copy or allocate, it just looks that way because the bytes crate is awesome.
    fn unwrap_iov(&self, len: usize, msg: &mut BytesMut) -> Result<BytesMut>;

    /// Return the remaining time this session has to live
    fn ttl(&self) -> Result<Duration>;
}

pub trait K5ServerCtx: K5Ctx {
    /// Return the user principal name of the client context associated with this server context.
    fn client(&self) -> Result<String>;
}

#[cfg(unix)]
mod unix;

#[cfg(unix)]
use crate::unix::{ClientCtx as ClientCtxImpl, ServerCtx as ServerCtxImpl};

#[cfg(windows)]
mod windows;

#[cfg(windows)]
use crate::windows::{ClientCtx as ClientCtxImpl, ServerCtx as ServerCtxImpl};

/// A Kerberos client context
#[derive(Clone, Debug)]
pub struct ClientCtx(ClientCtxImpl);

impl ClientCtx {
    /// Create a new client context. If `principal` is none then the credentials of
    /// the user the current process is running as will be used. `target_principal` is
    /// the service you intend to communicate with. This should be a service principal name as
    /// described by GSSAPI, e.g. publish/ken-ohki.ryu-oh.org@RYU-OH.ORG,
    /// the general form is <service>/host@REALM
    pub fn new(principal: Option<&str>, target_principal: &str) -> Result<Self> {
        Ok(ClientCtx(ClientCtxImpl::new(principal, target_principal)?))
    }
}

impl K5Ctx for ClientCtx {
    type Buf = <ClientCtxImpl as K5Ctx>::Buf;

    fn step(&self, token: Option<&[u8]>) -> Result<Option<Self::Buf>> {
        K5Ctx::step(&self.0, token)
    }

    fn wrap(&self, encrypt: bool, msg: &[u8]) -> Result<Self::Buf> {
        K5Ctx::wrap(&self.0, encrypt, msg)
    }

    fn wrap_iov(
        &self,
        encrypt: bool,
        header: &mut BytesMut,
        data: &mut BytesMut,
        padding: &mut BytesMut,
        trailer: &mut BytesMut,
    ) -> Result<()> {
        K5Ctx::wrap_iov(&self.0, encrypt, header, data, padding, trailer)
    }

    fn unwrap(&self, msg: &[u8]) -> Result<Self::Buf> {
        K5Ctx::unwrap(&self.0, msg)
    }

    fn unwrap_iov(&self, len: usize, msg: &mut BytesMut) -> Result<BytesMut> {
        K5Ctx::unwrap_iov(&self.0, len, msg)
    }

    fn ttl(&self) -> Result<Duration> {
        K5Ctx::ttl(&self.0)
    }
}

/// A Kerberos server context
#[derive(Clone, Debug)]
pub struct ServerCtx(ServerCtxImpl);

impl ServerCtx {
    /// Create a new server context. `principal` should be the service principal name
    /// assigned to the service this context is associated with. This is equivelent to
    /// the `target_principal` speficied in the client context. If it is left as `None`
    /// it will use the user running the current process.
    pub fn new(principal: Option<&str>) -> Result<Self> {
        Ok(ServerCtx(ServerCtxImpl::new(principal)?))
    }
}

impl K5Ctx for ServerCtx {
    type Buf = <ServerCtxImpl as K5Ctx>::Buf;

    fn step(&self, token: Option<&[u8]>) -> Result<Option<Self::Buf>> {
        K5Ctx::step(&self.0, token)
    }

    fn wrap(&self, encrypt: bool, msg: &[u8]) -> Result<Self::Buf> {
        K5Ctx::wrap(&self.0, encrypt, msg)
    }

    fn wrap_iov(
        &self,
        encrypt: bool,
        header: &mut BytesMut,
        data: &mut BytesMut,
        padding: &mut BytesMut,
        trailer: &mut BytesMut,
    ) -> Result<()> {
        K5Ctx::wrap_iov(&self.0, encrypt, header, data, padding, trailer)
    }

    fn unwrap(&self, msg: &[u8]) -> Result<Self::Buf> {
        K5Ctx::unwrap(&self.0, msg)
    }

    fn unwrap_iov(&self, len: usize, msg: &mut BytesMut) -> Result<BytesMut> {
        K5Ctx::unwrap_iov(&self.0, len, msg)
    }

    fn ttl(&self) -> Result<Duration> {
        K5Ctx::ttl(&self.0)
    }
}

impl K5ServerCtx for ServerCtx {
    fn client(&self) -> Result<String> {
        K5ServerCtx::client(&self.0)
    }
}

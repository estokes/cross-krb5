//! Cross platform Kerberos 5
//!
//! cross-krb5 is a single, simplified, and safe API for basic
//! Kerberos 5 services on Windows, and Unix like OSes. It provides
//! most of the flexibility of using gssapi and sspi directly, but
//! with the reduced complexity that comes from specifically targeting
//! only Kerberos.
//!
//! As well as providing a uniform API, services using cross-krb5
//! should interoperate across all the supported OSes transparantly,
//! and should interoperate with other services assuming they are not
//! platform specific.
//!
//! # Example
//! ```no_run
//! # use anyhow::Result;
//! use cross_krb5::{ClientCtx, ServerCtx, K5Ctx, K5ServerCtx};
//!
//!# fn run(spn: &str) -> Result<()> {
//! // setup the server context using the service principal name
//! let mut server = ServerCtx::new(Some(spn))?;
//! // The current user will request a service ticket for the spn
//! let mut client = ClientCtx::new(None, spn)?;
//! let mut server_tok: Option<<ClientCtx as K5Ctx>::Buffer> = None;
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
use bytes::{Buf, BytesMut};
use std::{time::Duration, ops::Deref};

pub trait K5Ctx {
    type Buffer: Deref<Target = [u8]> + Send + Sync;
    type IOVBuffer: Buf + Send + Sync;

    /// perform 1 step of initialization. `token` is the token you
    /// received from the other side, or `None` if you didn't receive
    /// one. If initialization is finished then `step` will return
    /// `Ok(None)`, and at that point the context is ready to use.  If
    /// `step` returns `Ok(Some(buf))` then initialization isn't
    /// finished and you are expected to send the contents of that
    /// buffer to the other side in order to finish it.  This may go
    /// on for several rounds of back and forth.
    fn step(&mut self, token: Option<&[u8]>) -> Result<Option<Self::Buffer>>;

    /// Wrap the specified message for sending to the other side. If
    /// `encrypt` is true then the contents will be encrypted. Even if
    /// `encrypt` is false the integrity of the contents are
    /// protected, if the message is altered in transit the other side
    /// will know.
    fn wrap(&mut self, encrypt: bool, msg: &[u8]) -> Result<Self::Buffer>;

    /// Wrap data in place using the underlying wrap_iov facility. If
    /// `encrypt` is true then the contents of `data` will be
    /// encrypted in place. `header`, `padding`, and `trailer` may be
    /// references to empty newly created `BytesMut` structures, they
    /// will be resized as needed, and can be reused for subsuquent
    /// calls in order to avoid further allocation. In order to send
    /// the message produced by `wrap_iov` you should send in order
    /// the header, data, padding, and trailer.
    ///
    /// # Examples
    /// ```no_run
    /// use bytes::{BytesMut, Buf};
    /// use cross_krb5::{ClientCtx, K5Ctx};
    /// # let mut ctx = unsafe { std::mem::zeroed::<ClientCtx>() };
    /// let mut data = BytesMut::from(b"hello world".as_slice());
    ///
    /// let buf = ctx.wrap_iov(true, data.split()).expect("failed to wrap_iov");
    /// // then use your prefered `writev` implementation to send.
    /// // e.g. tokio `write_buf` is quite convenient.
    /// ```
    ///
    /// Requires feature `krb5_iov`, which is part of the default
    /// feature set. However `krb5_iov` is not available on Mac OS. As
    /// such on Mac OS the api will still work, but it will be
    /// emulated using wrap, so it will not gain any performance
    /// benefit. On OSes where it is supported using
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
use crate::unix::{ClientCtx as ClientCtxImpl, ServerCtx as ServerCtxImpl};

#[cfg(windows)]
mod windows;

#[cfg(windows)]
use crate::windows::{ClientCtx as ClientCtxImpl, ServerCtx as ServerCtxImpl};

/// A Kerberos client context
#[derive(Clone, Debug)]
pub struct ClientCtx(ClientCtxImpl);

impl ClientCtx {
    /// Create a new client context. If `principal` is `None` then the
    /// credentials of the user running current process will be
    /// used. `target_principal` is the service principal name of the
    /// service you intend to communicate with. This should be an spn
    /// as described by GSSAPI,
    /// e.g. `"publish/ken-ohki.ryu-oh.org@RYU-OH.ORG"`, the general
    /// form is `service/host@REALM`
    pub fn new(principal: Option<&str>, target_principal: &str) -> Result<Self> {
        Ok(ClientCtx(ClientCtxImpl::new(principal, target_principal)?))
    }
}

impl K5Ctx for ClientCtx {
    type Buffer = <ClientCtxImpl as K5Ctx>::Buffer;
    type IOVBuffer = <ClientCtxImpl as K5Ctx>::IOVBuffer;

    fn step(&mut self, token: Option<&[u8]>) -> Result<Option<Self::Buffer>> {
        K5Ctx::step(&mut self.0, token)
    }

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

/// A Kerberos server context
#[derive(Clone, Debug)]
pub struct ServerCtx(ServerCtxImpl);

impl K5Ctx for ServerCtx {
    type Buffer = <ServerCtxImpl as K5Ctx>::Buffer;
    type IOVBuffer = <ServerCtxImpl as K5Ctx>::IOVBuffer;

    fn step(&mut self, token: Option<&[u8]>) -> Result<Option<Self::Buffer>> {
        K5Ctx::step(&mut self.0, token)
    }

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

impl ServerCtx {
    /// Create a new server context. `principal` should be the service
    /// principal name assigned to the service this context is
    /// associated with. This is equivelent to the `target_principal`
    /// speficied in the client context. If it is left as `None` it
    /// will use the user running the current process.
    pub fn new(principal: Option<&str>) -> Result<Self> {
        Ok(ServerCtx(ServerCtxImpl::new(principal)?))
    }
}

impl K5ServerCtx for ServerCtx {
    fn client(&mut self) -> Result<String> {
        K5ServerCtx::client(&mut self.0)
    }
}

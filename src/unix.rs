use super::{AcceptFlags, InitiateFlags, K5Ctx, K5ServerCtx, Step};
use anyhow::{anyhow, Error, Result};
use bytes::BytesMut;
use bytes::{self, buf::Chain, Buf as _};
#[cfg(feature = "iov")]
use libgssapi::util::{GssIov, GssIovFake, GssIovType};
use libgssapi::{
    context::{
        ClientCtx as GssClientCtx, CtxFlags, SecurityContext, ServerCtx as GssServerCtx,
    },
    credential::{Cred, CredUsage},
    name::Name,
    oid::{OidSet, GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL},
    util::Buf,
};
use std::{ops::Deref, time::Duration};

#[cfg(feature = "iov")]
fn wrap_iov(
    ctx: &mut impl SecurityContext,
    encrypt: bool,
    header: &mut BytesMut,
    data: &mut BytesMut,
    padding: &mut BytesMut,
    trailer: &mut BytesMut,
) -> Result<()> {
    let mut len_iovs = [
        GssIovFake::new(GssIovType::Header),
        GssIov::new(GssIovType::Data, &mut **data).as_fake(),
        GssIovFake::new(GssIovType::Padding),
        GssIovFake::new(GssIovType::Trailer),
    ];
    ctx.wrap_iov_length(encrypt, &mut len_iovs[..])?;
    header.resize(len_iovs[0].len(), 0x0);
    padding.resize(len_iovs[2].len(), 0x0);
    trailer.resize(len_iovs[3].len(), 0x0);
    let mut iovs = [
        GssIov::new(GssIovType::Header, &mut **header),
        GssIov::new(GssIovType::Data, &mut **data),
        GssIov::new(GssIovType::Padding, &mut **padding),
        GssIov::new(GssIovType::Trailer, &mut **trailer),
    ];
    Ok(ctx.wrap_iov(encrypt, &mut iovs)?)
}

#[cfg(not(feature = "iov"))]
fn wrap_iov(
    ctx: &mut impl SecurityContext,
    encrypt: bool,
    _header: &mut BytesMut,
    data: &mut BytesMut,
    _padding: &mut BytesMut,
    _trailer: &mut BytesMut,
) -> Result<()> {
    let token = ctx.wrap(encrypt, &**data)?;
    data.clear();
    Ok(data.extend_from_slice(&*token))
}

#[cfg(feature = "iov")]
fn unwrap_iov(
    ctx: &mut impl SecurityContext,
    len: usize,
    msg: &mut BytesMut,
) -> Result<BytesMut> {
    let (hdr_len, data_len) = {
        let mut iov = [
            GssIov::new(GssIovType::Stream, &mut msg[0..len]),
            GssIov::new(GssIovType::Data, &mut []),
        ];
        ctx.unwrap_iov(&mut iov[..])?;
        let hdr_len = iov[0].header_length(&iov[1]).unwrap();
        let data_len = iov[1].len();
        (hdr_len, data_len)
    };
    msg.advance(hdr_len);
    let data = msg.split_to(data_len);
    msg.advance(len - hdr_len - data_len);
    Ok(data) // return the decrypted contents
}

#[cfg(not(feature = "iov"))]
fn unwrap_iov(
    ctx: &mut impl SecurityContext,
    len: usize,
    msg: &mut BytesMut,
) -> Result<BytesMut> {
    let mut msg = msg.split_to(len);
    let decrypted = ctx.unwrap(&*msg)?;
    msg.clear();
    msg.extend_from_slice(&*decrypted);
    Ok(msg)
}

#[derive(Debug)]
pub(crate) struct PendingClientCtx(GssClientCtx);

impl PendingClientCtx {
    pub(crate) fn step(
        mut self,
        token: &[u8],
    ) -> Result<
        Step<
            (ClientCtx, Option<impl Deref<Target = [u8]>>),
            (PendingClientCtx, impl Deref<Target = [u8]>),
        >,
    > {
        fn cc(gss: GssClientCtx) -> ClientCtx {
            ClientCtx {
                gss,
                header: BytesMut::new(),
                padding: BytesMut::new(),
                trailer: BytesMut::new(),
            }
        }
        Ok(match self.0.step(Some(token), None)? {
            None => Step::Finished((cc(self.0), None)),
            Some(tok) if self.0.is_complete() => {
                Step::Finished((cc(self.0), Some(tok)))
            }
            Some(tok) => Step::Continue((self, tok)),
        })
    }
}

#[derive(Debug)]
pub struct ClientCtx {
    gss: GssClientCtx,
    header: BytesMut,
    padding: BytesMut,
    trailer: BytesMut,
}

impl ClientCtx {
    pub(crate) fn new(
        _flags: InitiateFlags,
        principal: Option<&str>,
        target_principal: &str,
        channel_bindings: Option<&[u8]>,
    ) -> Result<(PendingClientCtx, impl Deref<Target = [u8]>)> {
        let name = principal
            .map(|n| {
                Name::new(n.as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL))?
                    .canonicalize(Some(&GSS_MECH_KRB5))
            })
            .transpose()?;
        let target =
            Name::new(target_principal.as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL))?
                .canonicalize(Some(&GSS_MECH_KRB5))?;
        let cred = {
            let mut s = OidSet::new()?;
            s.add(&GSS_MECH_KRB5)?;
            Cred::acquire(name.as_ref(), None, CredUsage::Initiate, Some(&s))?
        };
        let mut gss = GssClientCtx::new(
            Some(cred),
            target,
            CtxFlags::GSS_C_MUTUAL_FLAG,
            Some(&GSS_MECH_KRB5),
        );
        let token =
            gss.step(None, channel_bindings)?.ok_or_else(|| anyhow!("expected token"))?;
        Ok((PendingClientCtx(gss), token))
    }
}

impl K5Ctx for ClientCtx {
    type Buffer = Buf;
    type IOVBuffer = Chain<BytesMut, Chain<BytesMut, Chain<BytesMut, BytesMut>>>;

    fn wrap(&mut self, encrypt: bool, msg: &[u8]) -> Result<Self::Buffer> {
        self.gss.wrap(encrypt, msg).map_err(|e| Error::from(e))
    }

    fn wrap_iov(&mut self, encrypt: bool, mut msg: BytesMut) -> Result<Self::IOVBuffer> {
        wrap_iov(
            &mut self.gss,
            encrypt,
            &mut self.header,
            &mut msg,
            &mut self.padding,
            &mut self.trailer,
        )?;
        Ok(self
            .header
            .split()
            .chain(msg.chain(self.padding.split().chain(self.trailer.split()))))
    }

    fn unwrap(&mut self, msg: &[u8]) -> Result<Self::Buffer> {
        self.gss.unwrap(msg).map_err(|e| Error::from(e))
    }

    fn unwrap_iov(&mut self, len: usize, msg: &mut BytesMut) -> Result<BytesMut> {
        unwrap_iov(&mut self.gss, len, msg)
    }

    fn ttl(&mut self) -> Result<Duration> {
        self.gss.lifetime().map_err(|e| Error::from(e))
    }
}

#[derive(Debug)]
pub(crate) struct PendingServerCtx(GssServerCtx);

impl PendingServerCtx {
    pub(crate) fn step(
        mut self,
        token: &[u8],
    ) -> Result<
        Step<
            (ServerCtx, Option<impl Deref<Target = [u8]>>),
            (PendingServerCtx, impl Deref<Target = [u8]>),
        >,
    > {
        fn cc(gss: GssServerCtx) -> ServerCtx {
            ServerCtx {
                gss,
                header: BytesMut::new(),
                padding: BytesMut::new(),
                trailer: BytesMut::new(),
            }
        }
        Ok(match self.0.step(token)? {
            None => Step::Finished((cc(self.0), None)),
            Some(tok) if self.0.is_complete() => {
                Step::Finished((cc(self.0), Some(tok)))
            }
            Some(tok) => Step::Continue((self, tok)),
        })
    }
}

#[derive(Debug)]
pub struct ServerCtx {
    gss: GssServerCtx,
    header: BytesMut,
    padding: BytesMut,
    trailer: BytesMut,
}

impl ServerCtx {
    pub(crate) fn new(
        _flags: AcceptFlags,
        principal: Option<&str>,
    ) -> Result<PendingServerCtx> {
        let name = principal
            .map(|principal| -> Result<Name> {
                Ok(Name::new(principal.as_bytes(), Some(&GSS_NT_KRB5_PRINCIPAL))?
                    .canonicalize(Some(&GSS_MECH_KRB5))?)
            })
            .transpose()?;
        let cred = {
            let mut s = OidSet::new()?;
            s.add(&GSS_MECH_KRB5)?;
            Cred::acquire(name.as_ref(), None, CredUsage::Accept, Some(&s))?
        };
        Ok(PendingServerCtx(GssServerCtx::new(cred)))
    }
}

impl K5Ctx for ServerCtx {
    type Buffer = Buf;
    type IOVBuffer = Chain<BytesMut, Chain<BytesMut, Chain<BytesMut, BytesMut>>>;

    fn wrap(&mut self, encrypt: bool, msg: &[u8]) -> Result<Self::Buffer> {
        self.gss.wrap(encrypt, msg).map_err(|e| Error::from(e))
    }

    fn wrap_iov(&mut self, encrypt: bool, mut msg: BytesMut) -> Result<Self::IOVBuffer> {
        wrap_iov(
            &mut self.gss,
            encrypt,
            &mut self.header,
            &mut msg,
            &mut self.padding,
            &mut self.trailer,
        )?;
        Ok(self
            .header
            .split()
            .chain(msg.chain(self.padding.split().chain(self.trailer.split()))))
    }

    fn unwrap(&mut self, msg: &[u8]) -> Result<Self::Buffer> {
        self.gss.unwrap(msg).map_err(|e| Error::from(e))
    }

    fn unwrap_iov(&mut self, len: usize, msg: &mut BytesMut) -> Result<BytesMut> {
        unwrap_iov(&mut self.gss, len, msg)
    }

    fn ttl(&mut self) -> Result<Duration> {
        self.gss.lifetime().map_err(|e| Error::from(e))
    }
}

impl K5ServerCtx for ServerCtx {
    fn client(&mut self) -> Result<String> {
        let n = self.gss.source_name().map_err(|e| Error::from(e))?;
        Ok(format!("{}", n))
    }
}

use super::{AcceptFlags, InitiateFlags, K5Cred, K5Ctx, K5ServerCtx, Step};
use anyhow::{anyhow, bail, Error, Result};
use bytes::BytesMut;
use bytes::{self, buf::Chain, Buf as _};
#[cfg(feature = "iov")]
use libgssapi::util::{GssIov, GssIovFake, GssIovType};
use libgssapi::{
    context::{
        ClientCtx as GssClientCtx, CtxFlags, SecurityContext, ServerCtx as GssServerCtx,
    },
    credential::{Cred as GssCred, CredUsage},
    name::Name,
    oid::{OidSet, GSS_MECH_KRB5, GSS_NT_KRB5_PRINCIPAL},
    util::Buf,
};
use std::{ops::Deref, time::Duration};

// Per RFC 2743 a requested context property is only a hint; the peer must
// confirm the mechanism actually granted it. We require a property unless the
// caller disabled it via the corresponding flag.
fn verify_granted(granted: CtxFlags, mutual: bool, confidential: bool) -> Result<()> {
    if mutual && !granted.contains(CtxFlags::GSS_C_MUTUAL_FLAG) {
        bail!("mutual authentication was required but not established");
    }
    if confidential && !granted.contains(CtxFlags::GSS_C_CONF_FLAG) {
        bail!("confidentiality was required but not established");
    }
    Ok(())
}

fn ensure_conf(confidential: bool, encrypt: bool) -> Result<()> {
    if encrypt && !confidential {
        bail!("encryption requested but the CONFIDENTIAL flag was not set");
    }
    Ok(())
}

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
    if len > msg.len() {
        bail!("unwrap_iov: len {} exceeds buffer length {}", len, msg.len());
    }
    let (hdr_len, data_len) = {
        let mut iov = [
            GssIov::new(GssIovType::Stream, &mut msg[0..len]),
            GssIov::new(GssIovType::Data, &mut []),
        ];
        ctx.unwrap_iov(&mut iov[..])?;
        let hdr_len = iov[0]
            .header_length(&iov[1])
            .ok_or_else(|| anyhow!("unwrap_iov: data buffer is not within the stream"))?;
        let data_len = iov[1].len();
        (hdr_len, data_len)
    };
    let pad_len = len
        .checked_sub(hdr_len)
        .and_then(|rest| rest.checked_sub(data_len))
        .ok_or_else(|| anyhow!("unwrap_iov: header + data exceed message length"))?;
    msg.advance(hdr_len);
    let data = msg.split_to(data_len);
    msg.advance(pad_len);
    Ok(data) // return the decrypted contents
}

#[cfg(not(feature = "iov"))]
fn unwrap_iov(
    ctx: &mut impl SecurityContext,
    len: usize,
    msg: &mut BytesMut,
) -> Result<BytesMut> {
    if len > msg.len() {
        bail!("unwrap_iov: len {} exceeds buffer length {}", len, msg.len());
    }
    let mut msg = msg.split_to(len);
    let decrypted = ctx.unwrap(&*msg)?;
    msg.clear();
    msg.extend_from_slice(&*decrypted);
    Ok(msg)
}

#[derive(Debug)]
pub(crate) struct Cred(GssCred);

impl Cred {
    fn acquire(principal: Option<&str>, usage: CredUsage) -> Result<Cred> {
        let name = principal
            .map(|n| {
                Name::new(n.as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL))?
                    .canonicalize(Some(GSS_MECH_KRB5))
            })
            .transpose()?;
        let s = OidSet::singleton(GSS_MECH_KRB5)?;
        Ok(GssCred::acquire(name.as_ref(), None, usage, Some(&s)).map(Cred::from)?)

    }
}

impl K5Cred for Cred {
    fn server_acquire(_flags: AcceptFlags, principal: Option<&str>) -> Result<Cred> {
        Self::acquire(principal, CredUsage::Accept)
    }
    
    fn client_acquire(_flags: InitiateFlags, principal: Option<&str>) -> Result<Cred> {
        Self::acquire(principal, CredUsage::Initiate)
    }
}

impl From<GssCred> for Cred {
    fn from(cred: GssCred) -> Self {
        Cred(cred)
    }
}

impl Into<GssCred> for Cred {
    fn into(self) -> GssCred {
        self.0
    }
}

#[derive(Debug)]
pub(crate) struct PendingClientCtx {
    gss: GssClientCtx,
    flags: InitiateFlags,
}

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
        fn cc(gss: GssClientCtx, confidential: bool) -> ClientCtx {
            ClientCtx {
                gss,
                confidential,
                header: BytesMut::new(),
                padding: BytesMut::new(),
                trailer: BytesMut::new(),
            }
        }
        let confidential = !self.flags.contains(InitiateFlags::DISABLE_CONFIDENTIALITY);
        let tok = self.gss.step(Some(token), None)?;
        if self.gss.is_complete() {
            verify_granted(
                self.gss.flags()?,
                !self.flags.contains(InitiateFlags::DISABLE_MUTUAL_AUTH),
                confidential,
            )?;
        }
        Ok(match tok {
            None => Step::Finished((cc(self.gss, confidential), None)),
            Some(tok) if self.gss.is_complete() => {
                Step::Finished((cc(self.gss, confidential), Some(tok)))
            }
            Some(tok) => Step::Continue((self, tok)),
        })
    }
}

#[derive(Debug)]
pub struct ClientCtx {
    gss: GssClientCtx,
    confidential: bool,
    header: BytesMut,
    padding: BytesMut,
    trailer: BytesMut,
}

impl ClientCtx {
    pub(crate) fn new(
        flags: InitiateFlags,
        principal: Option<&str>,
        target_principal: &str,
        channel_bindings: Option<&[u8]>,
    ) -> Result<(PendingClientCtx, impl Deref<Target = [u8]>)> {
        let cred = Cred::client_acquire(flags, principal)?;
        Self::new_with_cred(
            flags,
            cred,
            target_principal,
            channel_bindings,
        )
    }

    pub(crate) fn new_with_cred(
        flags: InitiateFlags,
        cred: Cred,
        target_principal: &str,
        channel_bindings: Option<&[u8]>,
    ) -> Result<(PendingClientCtx, impl Deref<Target=[u8]>)> {
        let target =
            Name::new(target_principal.as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL))?
                .canonicalize(Some(GSS_MECH_KRB5))?;
        // Integrity is fundamental to wrap/unwrap and always requested; mutual
        // auth and confidentiality are requested unless the caller disabled them.
        let mut req = CtxFlags::GSS_C_INTEG_FLAG;
        if !flags.contains(InitiateFlags::DISABLE_MUTUAL_AUTH) {
            req |= CtxFlags::GSS_C_MUTUAL_FLAG;
        }
        if !flags.contains(InitiateFlags::DISABLE_CONFIDENTIALITY) {
            req |= CtxFlags::GSS_C_CONF_FLAG;
        }
        let mut gss = GssClientCtx::new(Some(cred.0), target, req, Some(GSS_MECH_KRB5));
        let token =
            gss.step(None, channel_bindings)?.ok_or_else(|| anyhow!("expected token"))?;
        Ok((PendingClientCtx { gss, flags }, token))
    }
}

impl K5Ctx for ClientCtx {
    type Buffer = Buf;
    type IOVBuffer = Chain<BytesMut, Chain<BytesMut, Chain<BytesMut, BytesMut>>>;

    fn wrap(&mut self, encrypt: bool, msg: &[u8]) -> Result<Self::Buffer> {
        ensure_conf(self.confidential, encrypt)?;
        self.gss.wrap(encrypt, msg).map_err(|e| Error::from(e))
    }

    fn wrap_iov(&mut self, encrypt: bool, mut msg: BytesMut) -> Result<Self::IOVBuffer> {
        ensure_conf(self.confidential, encrypt)?;
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
pub(crate) struct PendingServerCtx {
    gss: GssServerCtx,
    flags: AcceptFlags,
    // owned because the acceptor may take several steps and the bindings
    // must outlive each gss_accept_sec_context call
    cb: Option<Vec<u8>>,
}

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
        fn cc(gss: GssServerCtx, confidential: bool) -> ServerCtx {
            ServerCtx {
                gss,
                confidential,
                header: BytesMut::new(),
                padding: BytesMut::new(),
                trailer: BytesMut::new(),
            }
        }
        let confidential = !self.flags.contains(AcceptFlags::DISABLE_CONFIDENTIALITY);
        let tok = self.gss.step(token, self.cb.as_deref())?;
        if self.gss.is_complete() {
            verify_granted(
                self.gss.flags()?,
                !self.flags.contains(AcceptFlags::DISABLE_MUTUAL_AUTH),
                confidential,
            )?;
        }
        Ok(match tok {
            None => Step::Finished((cc(self.gss, confidential), None)),
            Some(tok) if self.gss.is_complete() => {
                Step::Finished((cc(self.gss, confidential), Some(tok)))
            }
            Some(tok) => Step::Continue((self, tok)),
        })
    }
}

#[derive(Debug)]
pub struct ServerCtx {
    gss: GssServerCtx,
    confidential: bool,
    header: BytesMut,
    padding: BytesMut,
    trailer: BytesMut,
}

impl ServerCtx {
    pub(crate) fn new(
        flags: AcceptFlags,
        principal: Option<&str>,
        channel_bindings: Option<&[u8]>,
    ) -> Result<PendingServerCtx> {
        Self::new_with_cred(flags, Cred::server_acquire(flags, principal)?, channel_bindings)
    }

    pub(crate) fn new_with_cred(
        flags: AcceptFlags,
        cred: Cred,
        channel_bindings: Option<&[u8]>,
    ) -> Result<PendingServerCtx> {
        Ok(PendingServerCtx {
            gss: GssServerCtx::new(Some(cred.0)),
            flags,
            cb: channel_bindings.map(|cb| cb.to_vec()),
        })
    }
}

impl K5Ctx for ServerCtx {
    type Buffer = Buf;
    type IOVBuffer = Chain<BytesMut, Chain<BytesMut, Chain<BytesMut, BytesMut>>>;

    fn wrap(&mut self, encrypt: bool, msg: &[u8]) -> Result<Self::Buffer> {
        ensure_conf(self.confidential, encrypt)?;
        self.gss.wrap(encrypt, msg).map_err(|e| Error::from(e))
    }

    fn wrap_iov(&mut self, encrypt: bool, mut msg: BytesMut) -> Result<Self::IOVBuffer> {
        ensure_conf(self.confidential, encrypt)?;
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

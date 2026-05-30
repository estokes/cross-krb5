use super::{AcceptFlags, InitiateFlags, K5Cred, K5Ctx, K5ServerCtx, Step};
use anyhow::{anyhow, bail, Context, Result};
use bytes::{buf::Chain, Buf, BytesMut};
use std::{
    cell::Cell,
    default::Default,
    ffi::{c_void, OsString},
    fmt, mem,
    marker::PhantomData,
    ops::{Deref, Drop},
    os::windows::ffi::{OsStrExt, OsStringExt},
    ptr,
    time::Duration,
};
use windows::{
    core::{PCWSTR, PWSTR},
    Win32::{
        Foundation::{
            FILETIME, SEC_E_OK, SEC_I_COMPLETE_AND_CONTINUE, SEC_I_COMPLETE_NEEDED,
            SYSTEMTIME,
        },
        Globalization::lstrlenW,
        Security::{
            Authentication::Identity::{
                AcceptSecurityContext, AcquireCredentialsHandleW, CompleteAuthToken,
                DecryptMessage, DeleteSecurityContext, EncryptMessage, FreeContextBuffer,
                FreeCredentialsHandle, InitializeSecurityContextW,
                QueryContextAttributesW, QueryCredentialsAttributesW,
                QuerySecurityPackageInfoW, SecBuffer, SecBufferDesc,
                SecPkgContext_NativeNamesW, SecPkgContext_NegotiationInfoW,
                SecPkgContext_Sizes,
                SecPkgCredentials_NamesW, ASC_REQ_CONFIDENTIALITY, ASC_REQ_FLAGS,
                ASC_REQ_MUTUAL_AUTH, ASC_RET_CONFIDENTIALITY, ASC_RET_MUTUAL_AUTH,
                ISC_REQ_CONFIDENTIALITY, ISC_REQ_FLAGS, ISC_REQ_MUTUAL_AUTH,
                ISC_RET_CONFIDENTIALITY, ISC_RET_MUTUAL_AUTH, KERB_WRAP_NO_ENCRYPT,
                SECBUFFER_CHANNEL_BINDINGS, SECBUFFER_DATA, SECBUFFER_PADDING,
                SECBUFFER_STREAM, SECBUFFER_TOKEN, SECBUFFER_VERSION,
                SECPKG_ATTR_NATIVE_NAMES, SECPKG_ATTR_NEGOTIATION_INFO,
                SECPKG_ATTR_SIZES, SECPKG_CRED_ATTR_NAMES,
                SECPKG_CRED_INBOUND, SECPKG_CRED_OUTBOUND, SECURITY_NATIVE_DREP,
                SEC_CHANNEL_BINDINGS,
            },
            Credentials::SecHandle,
        },
        System::{
            Diagnostics::Debug::{
                FormatMessageW, FORMAT_MESSAGE_FROM_SYSTEM, FORMAT_MESSAGE_IGNORE_INSERTS,
            },
            SystemInformation::GetSystemTime,
            SystemServices::{LANG_NEUTRAL, SUBLANG_NEUTRAL},
            Time::{SystemTimeToFileTime, SystemTimeToTzSpecificLocalTime},
        },
    },
};

fn failed(res: i32) -> bool {
    res < 0
}

fn ensure_conf(confidential: bool, encrypt: bool) -> Result<()> {
    if encrypt && !confidential {
        bail!("encryption requested but the CONFIDENTIAL flag was not set");
    }
    Ok(())
}

// Build the SECBUFFER_CHANNEL_BINDINGS payload SSPI expects: a
// SEC_CHANNEL_BINDINGS header followed by the application data. The returned
// buffer must stay alive for the duration of the Init/Accept call that
// references it.
fn channel_bindings_buf(cb_token: &[u8]) -> BytesMut {
    let mut buf =
        BytesMut::with_capacity(mem::size_of::<SEC_CHANNEL_BINDINGS>() + cb_token.len());
    let mut sec_cb = SEC_CHANNEL_BINDINGS::default();
    sec_cb.dwApplicationDataOffset = mem::size_of::<SEC_CHANNEL_BINDINGS>() as u32;
    sec_cb.cbApplicationDataLength = cb_token.len() as u32;
    buf.extend(unsafe {
        std::slice::from_raw_parts(
            &sec_cb as *const SEC_CHANNEL_BINDINGS as *const u8,
            mem::size_of::<SEC_CHANNEL_BINDINGS>(),
        )
    });
    buf.extend(cb_token);
    buf
}

unsafe fn string_from_wstr(s: *mut u16) -> String {
    let slen = lstrlenW(PCWSTR(s));
    let slice = &*ptr::slice_from_raw_parts(s, slen as usize);
    OsString::from_wide(slice).to_string_lossy().to_string()
}

fn str_to_wstr(s: &str) -> Vec<u16> {
    let mut v = OsString::from(s).encode_wide().collect::<Vec<_>>();
    v.push(0);
    v
}

fn format_error(error: i32) -> String {
    const BUF: usize = 512;
    let mut msg = [0u16; BUF];
    unsafe {
        FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            None,
            error as u32,
            (LANG_NEUTRAL << 10) | SUBLANG_NEUTRAL,
            PWSTR(msg.as_mut_ptr()),
            (BUF - 1) as u32,
            None,
        );
    }
    unsafe { string_from_wstr(msg.as_mut_ptr()) }
}

#[derive(Debug)]
pub(crate) struct Cred(SecHandle);

impl Drop for Cred {
    fn drop(&mut self) {
        unsafe {
            let _ = FreeCredentialsHandle(&mut self.0);
        }
    }
}

impl From<SecHandle> for Cred {
    fn from(handle: SecHandle) -> Self {
        Cred(handle)
    }
}

impl Into<SecHandle> for Cred {
    fn into(self) -> SecHandle {
        // SecHandle is Copy, so returning self.0 alone would leave `self` to
        // drop and run FreeCredentialsHandle on the handle we just handed out.
        // Forget self so the caller takes ownership of a live handle.
        let handle = self.0;
        mem::forget(self);
        handle
    }
}

impl Cred {
    fn acquire(negotiate: bool, principal: Option<&str>, server: bool) -> Result<Cred> {
        let mut cred = SecHandle::default();
        // `principal` must stay live until after AcquireCredentialsHandleW: the
        // pointer below borrows into its buffer. Binding it here (rather than
        // moving the Vec into a `.map` closure) keeps it alive for the call.
        let mut principal = principal.map(str_to_wstr);
        let principal_ptr =
            principal.as_mut().map(|p| p.as_mut_ptr()).unwrap_or(ptr::null_mut());
        let package = str_to_wstr(if negotiate { "Negotiate" } else { "Kerberos" });
        let dir = if server { SECPKG_CRED_INBOUND } else { SECPKG_CRED_OUTBOUND };
        let mut lifetime = 0i64;
        unsafe {
            AcquireCredentialsHandleW(
                PCWSTR(principal_ptr),
                PCWSTR(package.as_ptr()),
                dir,
                None,
                None,
                None,
                None,
                &mut cred,
                Some(&mut lifetime),
            )
            .context("acquiring credentials")?
        };
        Ok(Cred(cred))
    }

    fn _name(&mut self) -> Result<String> {
        let mut names = SecPkgCredentials_NamesW::default();
        unsafe {
            QueryCredentialsAttributesW(
                &mut self.0,
                SECPKG_CRED_ATTR_NAMES,
                &mut names as *mut _ as *mut c_void,
            )
            .context("querying credential names")?;
            Ok(string_from_wstr(names.sUserName))
        }
    }
}

impl K5Cred for Cred {
    fn server_acquire(flags: AcceptFlags, principal: Option<&str>) -> anyhow::Result<Self> {
        Self::acquire(flags.contains(AcceptFlags::NEGOTIATE_TOKEN), principal, true)
    }

    fn client_acquire(flags: InitiateFlags, principal: Option<&str>) -> anyhow::Result<Self> {
        Self::acquire(flags.contains(InitiateFlags::NEGOTIATE_TOKEN), principal, false)
    }
}

fn alloc_krb5_buf() -> Result<Vec<u8>> {
    let mut pkg = str_to_wstr("Kerberos");
    let ifo = unsafe {
        QuerySecurityPackageInfoW(PCWSTR(pkg.as_mut_ptr()))
            .context("querying security package info")?
    };
    let max_len = unsafe { (*ifo).cbMaxToken };
    unsafe {
        FreeContextBuffer(ifo as *mut c_void).context("freeing the package buffer")?;
    }
    let mut buf = Vec::with_capacity(max_len as usize);
    buf.extend((0..max_len).into_iter().map(|_| 0));
    Ok(buf)
}

fn query_pkg_sizes(ctx: &mut SecHandle, sz: &mut SecPkgContext_Sizes) -> Result<()> {
    unsafe {
        QueryContextAttributesW(ctx, SECPKG_ATTR_SIZES, sz as *mut _ as *mut c_void)
            .context("querying package sizes")?
    };
    Ok(())
}

// With the Negotiate (SPNEGO) package SSPI may select NTLM instead of
// Kerberos. We only support Kerberos, so confirm the negotiated mechanism
// and refuse anything else rather than silently running on a weaker protocol.
fn verify_kerberos_negotiated(ctx: &mut SecHandle) -> Result<()> {
    let mut info = SecPkgContext_NegotiationInfoW::default();
    unsafe {
        QueryContextAttributesW(
            ctx,
            SECPKG_ATTR_NEGOTIATION_INFO,
            &mut info as *mut _ as *mut c_void,
        )
        .context("querying negotiation info")?;
    }
    if info.PackageInfo.is_null() {
        bail!("negotiate did not report which security package it selected");
    }
    // Copy the name out before freeing the SSPI-allocated package info.
    let name = unsafe { string_from_wstr((*info.PackageInfo).Name) };
    unsafe {
        let _ = FreeContextBuffer(info.PackageInfo as *mut c_void);
    }
    if name != "Kerberos" {
        bail!("negotiate selected {name} instead of Kerberos");
    }
    Ok(())
}

fn wrap_iov(
    ctx: &mut SecHandle,
    sizes: &SecPkgContext_Sizes,
    encrypt: bool,
    header: &mut BytesMut,
    data: &mut BytesMut,
    padding: &mut BytesMut,
) -> Result<()> {
    header.resize(sizes.cbSecurityTrailer as usize, 0);
    padding.resize(sizes.cbBlockSize as usize, 0);
    let mut buffers = [
        SecBuffer {
            BufferType: SECBUFFER_TOKEN,
            cbBuffer: sizes.cbSecurityTrailer,
            pvBuffer: header.as_mut_ptr() as *mut c_void,
        },
        SecBuffer {
            BufferType: SECBUFFER_DATA,
            cbBuffer: data.len() as u32,
            pvBuffer: data.as_mut_ptr() as *mut c_void,
        },
        SecBuffer {
            BufferType: SECBUFFER_PADDING,
            cbBuffer: sizes.cbBlockSize,
            pvBuffer: padding.as_mut_ptr() as *mut c_void,
        },
    ];
    let mut buf_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 3,
        pBuffers: buffers.as_mut_ptr(),
    };
    let flags = if !encrypt { KERB_WRAP_NO_ENCRYPT } else { 0 };
    let res = unsafe { EncryptMessage(ctx, flags, &mut buf_desc, 0) };
    if failed(res.0) {
        bail!("EncryptMessage failed {}", format_error(res.0))
    }
    header.resize(buffers[0].cbBuffer as usize, 0);
    assert_eq!(buffers[1].cbBuffer as usize, data.len());
    padding.resize(buffers[2].cbBuffer as usize, 0);
    Ok(())
}

fn wrap(
    ctx: &mut SecHandle,
    sizes: &SecPkgContext_Sizes,
    encrypt: bool,
    msg: &[u8],
) -> Result<BytesMut> {
    let mut header = BytesMut::new();
    header.resize(sizes.cbSecurityTrailer as usize, 0);
    let mut data = BytesMut::from(msg);
    let mut padding = BytesMut::new();
    padding.resize(sizes.cbBlockSize as usize, 0);
    wrap_iov(ctx, sizes, encrypt, &mut header, &mut data, &mut padding)?;
    let mut msg = BytesMut::with_capacity(header.len() + data.len() + padding.len());
    msg.extend_from_slice(&*header);
    msg.extend_from_slice(&*data);
    msg.extend_from_slice(&*padding);
    Ok(msg)
}

fn unwrap_iov(ctx: &mut SecHandle, len: usize, msg: &mut BytesMut) -> Result<BytesMut> {
    if len > msg.len() {
        bail!("unwrap_iov: len {} exceeds buffer length {}", len, msg.len());
    }
    let mut bufs = [
        SecBuffer {
            BufferType: SECBUFFER_STREAM,
            cbBuffer: len as u32,
            pvBuffer: &mut msg[0..len] as *mut _ as *mut c_void,
        },
        SecBuffer { BufferType: SECBUFFER_DATA, cbBuffer: 0, pvBuffer: ptr::null_mut() },
    ];
    let mut bufs_desc = SecBufferDesc {
        ulVersion: SECBUFFER_VERSION,
        cBuffers: 2,
        pBuffers: bufs.as_mut_ptr(),
    };
    let mut qop: u32 = 0;
    let res = unsafe { DecryptMessage(ctx, &mut bufs_desc, 0, Some(&mut qop)) };
    if failed(res.0) {
        bail!("decrypt message failed {}", format_error(res.0))
    }
    let hdr_len = (bufs[1].pvBuffer as usize)
        .checked_sub(bufs[0].pvBuffer as usize)
        .ok_or_else(|| anyhow!("unwrap_iov: data buffer precedes the stream start"))?;
    let data_len = bufs[1].cbBuffer as usize;
    let pad_len = len
        .checked_sub(hdr_len)
        .and_then(|rest| rest.checked_sub(data_len))
        .ok_or_else(|| anyhow!("unwrap_iov: header + data exceed message length"))?;
    msg.advance(hdr_len);
    let data = msg.split_to(data_len);
    msg.advance(pad_len); // padding
    Ok(data)
}

// `expires` is the SSPI ptsExpiry timestamp. Counterintuitively, the Kerberos
// SSP reports it in LOCAL time, not UTC (verified against a live KDC), so we
// must compare it against a local-time "now": convert UTC system time to local
// before turning it into a FILETIME. Do NOT "simplify" this to plain UTC — that
// reintroduces an off-by-(UTC offset) error in the reported ttl.
fn convert_lifetime(expires: i64) -> Result<Duration> {
    let mut lt = SYSTEMTIME::default();
    let mut ft = FILETIME::default();
    unsafe {
        let st = GetSystemTime();
        SystemTimeToTzSpecificLocalTime(None, &st, &mut lt)
            .context("converting system time to local time")?;
        SystemTimeToFileTime(&lt, &mut ft)
            .context("converting system time to file time")?;
        let now: u64 = ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64);
        if expires as u64 <= now {
            Ok(Duration::from_secs(0))
        } else {
            // FILETIME deltas are in 100ns units, so seconds = ticks / 1e7.
            Ok(Duration::from_secs((expires as u64 - now) / 10_000_000))
        }
    }
}

#[derive(Debug)]
pub(crate) struct PendingClientCtx(ClientCtx);

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
        Ok(match self.0.do_step(InputData::Subsequent(token))? {
            None => Step::Finished((self.0, None)),
            Some(tok) if self.0.done => Step::Finished((self.0, Some(tok))),
            Some(tok) => Step::Continue((self, tok)),
        })
    }
}

// An SSPI security context must not be used concurrently from multiple
// threads. Unlike unix, where SecHandle's analogue is a raw pointer that
// is already !Sync, SecHandle is a pair of integers and so the contexts
// would otherwise be auto-Sync. This marker removes Sync while retaining
// Send, keeping the cross platform API uniform (see CHANGELOG 0.5.0).
type NotSync = PhantomData<Cell<()>>;

pub struct ClientCtx {
    ctx: SecHandle,
    cred: Cred,
    target: Vec<u16>,
    flags: InitiateFlags,
    attrs: u32,
    lifetime: i64,
    buf: Vec<u8>,
    done: bool,
    sizes: SecPkgContext_Sizes,
    header: BytesMut,
    padding: BytesMut,
    not_sync: NotSync,
}

impl Drop for ClientCtx {
    fn drop(&mut self) {
        unsafe {
            let _ = DeleteSecurityContext(&mut self.ctx);
        }
    }
}

impl fmt::Debug for ClientCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientCtx")
    }
}

#[derive(Clone, Copy, Debug)]
enum InputData<'a> {
    Initial(Option<&'a [u8]>),
    Subsequent(&'a [u8]),
}

impl ClientCtx {
    pub(crate) fn new(
        flags: InitiateFlags,
        principal: Option<&str>,
        target_principal: &str,
        cb_token: Option<&[u8]>,
    ) -> Result<(PendingClientCtx, impl Deref<Target = [u8]>)> {
        Self::new_with_cred(
            flags,
            Cred::client_acquire(flags, principal)?,
            target_principal,
            cb_token,
        )
    }

    pub(crate) fn new_with_cred(
        flags: InitiateFlags,
        cred: Cred,
        target_principal: &str,
        cb_token: Option<&[u8]>,
    ) -> Result<(PendingClientCtx, impl Deref<Target = [u8]>)> {
        let mut ctx = ClientCtx {
            ctx: SecHandle::default(),
            cred,
            target: str_to_wstr(target_principal),
            flags,
            attrs: 0,
            lifetime: 0,
            buf: alloc_krb5_buf()?,
            done: false,
            sizes: SecPkgContext_Sizes::default(),
            header: BytesMut::new(),
            padding: BytesMut::new(),
            not_sync: PhantomData,
        };
        let token = ctx
            .do_step(InputData::Initial(cb_token))?
            .ok_or_else(|| anyhow!("expected token"))?;
        Ok((PendingClientCtx(ctx), token))
    }

    fn do_step(&mut self, data: InputData) -> Result<Option<BytesMut>> {
        if self.done {
            return Ok(None);
        }
        for i in 0..self.buf.len() {
            self.buf[i] = 0;
        }
        let mut out_buf = SecBuffer {
            cbBuffer: self.buf.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: self.buf.as_mut_ptr() as *mut c_void,
        };
        let mut out_buf_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut out_buf,
        };
        let cbt_buf;
        let mut in_buf = match data {
            InputData::Initial(None) => SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: ptr::null_mut(),
            },
            InputData::Initial(Some(cb_token)) => {
                cbt_buf = channel_bindings_buf(cb_token);
                SecBuffer {
                    cbBuffer: cbt_buf.len() as u32,
                    BufferType: SECBUFFER_CHANNEL_BINDINGS,
                    pvBuffer: cbt_buf.as_ptr() as *mut c_void,
                }
            }
            InputData::Subsequent(tok) => SecBuffer {
                cbBuffer: tok.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: tok.as_ptr() as *mut c_void,
            },
        };
        let in_buf_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut in_buf,
        };
        let ctx_ptr = match data {
            InputData::Initial(_) => None,
            InputData::Subsequent(_) => Some(&self.ctx as *const _),
        };
        let in_buf_ptr = match data {
            InputData::Initial(Some(_)) | InputData::Subsequent(_) => {
                Some(&in_buf_desc as *const _)
            }
            InputData::Initial(None) => None,
        };
        // Request mutual auth / confidentiality unless the caller disabled them.
        let want_mutual = !self.flags.contains(InitiateFlags::DISABLE_MUTUAL_AUTH);
        let want_conf = !self.flags.contains(InitiateFlags::DISABLE_CONFIDENTIALITY);
        let mut req = ISC_REQ_FLAGS(0);
        if want_mutual {
            req |= ISC_REQ_MUTUAL_AUTH;
        }
        if want_conf {
            req |= ISC_REQ_CONFIDENTIALITY;
        }
        let res = unsafe {
            InitializeSecurityContextW(
                Some(&mut self.cred.0),
                ctx_ptr,
                Some(self.target.as_ptr()),
                req,
                0,
                SECURITY_NATIVE_DREP,
                in_buf_ptr,
                0,
                Some(&mut self.ctx),
                Some(&mut out_buf_desc),
                &mut self.attrs,
                Some(&mut self.lifetime),
            )
        };
        if failed(res.0) {
            bail!("ClientCtx::step failed {}", format_error(res.0))
        }
        // Some mechanisms require the generated token to be finalized before
        // it is sent. SEC_E_OK and SEC_I_COMPLETE_NEEDED both mean the context
        // is established; the *_CONTINUE variants mean another leg follows.
        if res == SEC_I_COMPLETE_NEEDED || res == SEC_I_COMPLETE_AND_CONTINUE {
            unsafe {
                CompleteAuthToken(&self.ctx, &out_buf_desc)
                    .context("completing auth token")?;
            }
        }
        if res == SEC_E_OK || res == SEC_I_COMPLETE_NEEDED {
            // A requested property is only a hint; per RFC 2743 the initiator
            // must confirm the mechanism actually granted what we required.
            if want_mutual && self.attrs & ISC_RET_MUTUAL_AUTH == 0 {
                bail!("mutual authentication was required but not established");
            }
            if want_conf && self.attrs & ISC_RET_CONFIDENTIALITY == 0 {
                bail!("confidentiality was required but not established");
            }
            // SPNEGO can fall back to NTLM; insist on Kerberos when negotiating.
            if self.flags.contains(InitiateFlags::NEGOTIATE_TOKEN) {
                verify_kerberos_negotiated(&mut self.ctx)?;
            }
            query_pkg_sizes(&mut self.ctx, &mut self.sizes)?;
            self.done = true;
        }
        if out_buf.cbBuffer > 0 {
            Ok(Some(BytesMut::from(&self.buf[0..(out_buf.cbBuffer as usize)])))
        } else if self.done {
            Ok(None)
        } else {
            bail!("ClientCtx::step no token was generated but we are not done")
        }
    }
}

impl K5Ctx for ClientCtx {
    type Buffer = BytesMut;
    type IOVBuffer = Chain<BytesMut, Chain<BytesMut, BytesMut>>;

    fn wrap(&mut self, encrypt: bool, msg: &[u8]) -> Result<BytesMut> {
        ensure_conf(!self.flags.contains(InitiateFlags::DISABLE_CONFIDENTIALITY), encrypt)?;
        wrap(&mut self.ctx, &self.sizes, encrypt, msg)
    }

    fn wrap_iov(&mut self, encrypt: bool, mut msg: BytesMut) -> Result<Self::IOVBuffer> {
        ensure_conf(!self.flags.contains(InitiateFlags::DISABLE_CONFIDENTIALITY), encrypt)?;
        wrap_iov(
            &mut self.ctx,
            &mut self.sizes,
            encrypt,
            &mut self.header,
            &mut msg,
            &mut self.padding,
        )?;
        Ok(self.header.split().chain(msg.chain(self.padding.split())))
    }

    fn unwrap_iov(&mut self, len: usize, msg: &mut BytesMut) -> Result<BytesMut> {
        unwrap_iov(&mut self.ctx, len, msg)
    }

    fn unwrap(&mut self, msg: &[u8]) -> Result<BytesMut> {
        let mut buf = BytesMut::from(msg);
        self.unwrap_iov(buf.len(), &mut buf)
    }

    fn ttl(&mut self) -> Result<Duration> {
        convert_lifetime(self.lifetime)
    }
}

pub(crate) struct PendingServerCtx(ServerCtx);

impl PendingServerCtx {
    pub(crate) fn step(
        mut self,
        tok: &[u8],
    ) -> Result<
        Step<
            (ServerCtx, Option<impl Deref<Target = [u8]>>),
            (PendingServerCtx, impl Deref<Target = [u8]>),
        >,
    > {
        Ok(match self.0.do_step(tok)? {
            None => Step::Finished((self.0, None)),
            Some(tok) if self.0.done => Step::Finished((self.0, Some(tok))),
            Some(tok) => Step::Continue((self, tok)),
        })
    }
}

pub struct ServerCtx {
    ctx: SecHandle,
    cred: Cred,
    flags: AcceptFlags,
    cb_token: Option<Vec<u8>>,
    buf: Vec<u8>,
    attrs: u32,
    lifetime: i64,
    done: bool,
    sizes: SecPkgContext_Sizes,
    header: BytesMut,
    padding: BytesMut,
    not_sync: NotSync,
}

impl Drop for ServerCtx {
    fn drop(&mut self) {
        unsafe {
            let _ = DeleteSecurityContext(&mut self.ctx);
        }
    }
}

impl fmt::Debug for ServerCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServerCtx")
    }
}

impl ServerCtx {
    pub(crate) fn new(
        flags: AcceptFlags,
        principal: Option<&str>,
        channel_bindings: Option<&[u8]>,
    ) -> Result<PendingServerCtx> {
        Self::new_with_cred(
            flags,
            Cred::server_acquire(flags, principal)?,
            channel_bindings,
        )
    }

    pub(crate) fn new_with_cred(
        flags: AcceptFlags,
        cred: Cred,
        channel_bindings: Option<&[u8]>,
    ) -> Result<PendingServerCtx> {
        Ok(PendingServerCtx(ServerCtx {
            ctx: SecHandle::default(),
            cred,
            flags,
            cb_token: channel_bindings.map(|cb| cb.to_vec()),
            buf: alloc_krb5_buf()?,
            attrs: 0,
            lifetime: 0,
            done: false,
            sizes: SecPkgContext_Sizes::default(),
            header: BytesMut::new(),
            padding: BytesMut::new(),
            not_sync: PhantomData,
        }))
    }

    fn do_step(&mut self, tok: &[u8]) -> Result<Option<BytesMut>> {
        if self.done {
            return Ok(None);
        }
        for i in 0..self.buf.len() {
            self.buf[i] = 0;
        }
        let mut out_buf = SecBuffer {
            cbBuffer: self.buf.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: self.buf.as_mut_ptr() as *mut c_void,
        };
        let mut out_buf_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut out_buf,
        };
        // The client's token is always present; the channel bindings, if any,
        // go in a second input buffer so the acceptor can verify them.
        let cbt_buf;
        let mut in_bufs = [
            SecBuffer {
                cbBuffer: tok.len() as u32,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: tok.as_ptr() as *mut c_void,
            },
            SecBuffer {
                cbBuffer: 0,
                BufferType: SECBUFFER_TOKEN,
                pvBuffer: ptr::null_mut(),
            },
        ];
        let n_in_bufs = match &self.cb_token {
            Some(cb) => {
                cbt_buf = channel_bindings_buf(cb);
                in_bufs[1] = SecBuffer {
                    cbBuffer: cbt_buf.len() as u32,
                    BufferType: SECBUFFER_CHANNEL_BINDINGS,
                    pvBuffer: cbt_buf.as_ptr() as *mut c_void,
                };
                2
            }
            None => 1,
        };
        let in_buf_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: n_in_bufs,
            pBuffers: in_bufs.as_mut_ptr(),
        };
        let dfsh = SecHandle::default();
        let ctx_ptr =
            if self.ctx.dwLower == dfsh.dwLower && self.ctx.dwUpper == dfsh.dwUpper {
                None
            } else {
                Some(&self.ctx as *const _)
            };
        // Request mutual auth / confidentiality unless the caller disabled them.
        let want_mutual = !self.flags.contains(AcceptFlags::DISABLE_MUTUAL_AUTH);
        let want_conf = !self.flags.contains(AcceptFlags::DISABLE_CONFIDENTIALITY);
        let mut req = ASC_REQ_FLAGS(0);
        if want_mutual {
            req |= ASC_REQ_MUTUAL_AUTH;
        }
        if want_conf {
            req |= ASC_REQ_CONFIDENTIALITY;
        }
        let res = unsafe {
            AcceptSecurityContext(
                Some(&self.cred.0),
                ctx_ptr,
                Some(&in_buf_desc),
                req,
                SECURITY_NATIVE_DREP,
                Some(&mut self.ctx),
                Some(&mut out_buf_desc),
                &mut self.attrs,
                Some(&mut self.lifetime),
            )
        };
        if failed(res.0) {
            bail!("ServerCtx::step failed {}", format_error(res.0));
        }
        if res == SEC_I_COMPLETE_NEEDED || res == SEC_I_COMPLETE_AND_CONTINUE {
            unsafe {
                CompleteAuthToken(&self.ctx, &out_buf_desc)
                    .context("completing auth token")?;
            }
        }
        if res == SEC_E_OK || res == SEC_I_COMPLETE_NEEDED {
            // The acceptor must likewise confirm the properties it required
            // were granted before treating the context as usable.
            if want_mutual && self.attrs & ASC_RET_MUTUAL_AUTH == 0 {
                bail!("mutual authentication was required but not established");
            }
            if want_conf && self.attrs & ASC_RET_CONFIDENTIALITY == 0 {
                bail!("confidentiality was required but not established");
            }
            if self.flags.contains(AcceptFlags::NEGOTIATE_TOKEN) {
                verify_kerberos_negotiated(&mut self.ctx)?;
            }
            query_pkg_sizes(&mut self.ctx, &mut self.sizes)?;
            self.done = true;
        }
        if out_buf.cbBuffer > 0 {
            Ok(Some(BytesMut::from(&self.buf[0..(out_buf.cbBuffer as usize)])))
        } else if self.done {
            Ok(None)
        } else {
            bail!("ServerCtx::step no token was generated but we are not done")
        }
    }
}

impl K5Ctx for ServerCtx {
    type Buffer = BytesMut;
    type IOVBuffer = Chain<BytesMut, Chain<BytesMut, BytesMut>>;

    fn wrap(&mut self, encrypt: bool, msg: &[u8]) -> Result<BytesMut> {
        ensure_conf(!self.flags.contains(AcceptFlags::DISABLE_CONFIDENTIALITY), encrypt)?;
        wrap(&mut self.ctx, &self.sizes, encrypt, msg)
    }

    fn wrap_iov(&mut self, encrypt: bool, mut msg: BytesMut) -> Result<Self::IOVBuffer> {
        ensure_conf(!self.flags.contains(AcceptFlags::DISABLE_CONFIDENTIALITY), encrypt)?;
        wrap_iov(
            &mut self.ctx,
            &mut self.sizes,
            encrypt,
            &mut self.header,
            &mut msg,
            &mut self.padding,
        )?;
        Ok(self.header.split().chain(msg.chain(self.padding.split())))
    }

    fn unwrap(&mut self, msg: &[u8]) -> Result<BytesMut> {
        let mut buf = BytesMut::from(msg);
        self.unwrap_iov(buf.len(), &mut buf)
    }

    fn unwrap_iov(&mut self, len: usize, msg: &mut BytesMut) -> Result<BytesMut> {
        unwrap_iov(&mut self.ctx, len, msg)
    }

    fn ttl(&mut self) -> Result<Duration> {
        convert_lifetime(self.lifetime)
    }
}

impl K5ServerCtx for ServerCtx {
    fn client(&mut self) -> Result<String> {
        let mut names = SecPkgContext_NativeNamesW::default();
        unsafe {
            QueryContextAttributesW(
                &mut self.ctx,
                SECPKG_ATTR_NATIVE_NAMES,
                &mut names as *mut _ as *mut c_void,
            )
            .context("looking up client names")?;
            let client = string_from_wstr(names.sClientName);
            // sClientName and sServerName are variable-sized members the SSP
            // allocates; per the QueryContextAttributes contract the caller
            // must release them with FreeContextBuffer or they leak.
            if !names.sClientName.is_null() {
                let _ = FreeContextBuffer(names.sClientName as *mut c_void);
            }
            if !names.sServerName.is_null() {
                let _ = FreeContextBuffer(names.sServerName as *mut c_void);
            }
            Ok(client)
        }
    }
}

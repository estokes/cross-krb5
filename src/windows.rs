use super::{K5Ctx, K5ServerCtx};
use anyhow::{anyhow, bail, Result};
use bytes::{buf::Chain, Buf, BytesMut};
use std::{
    default::Default,
    ffi::{c_void, OsString},
    fmt, mem,
    ops::{Deref, Drop},
    os::windows::ffi::{OsStrExt, OsStringExt},
    ptr,
    time::Duration,
};
use windows::Win32::{
    Foundation::{
        GetLastError, FILETIME, PWSTR, SEC_E_OK, SEC_I_COMPLETE_AND_CONTINUE,
        SEC_I_COMPLETE_NEEDED, SYSTEMTIME,
    },
    Globalization::lstrlenW,
    Security::{
        Authentication::Identity::{
            AcceptSecurityContext, AcquireCredentialsHandleW, CompleteAuthToken,
            DecryptMessage, DeleteSecurityContext, EncryptMessage, FreeContextBuffer,
            FreeCredentialsHandle, InitializeSecurityContextW, QueryContextAttributesW,
            QueryCredentialsAttributesW, QuerySecurityPackageInfoW, SecBuffer,
            SecBufferDesc, SecPkgContext_NativeNamesW, SecPkgContext_Sizes,
            SecPkgCredentials_NamesW, SecPkgInfoW, ACCEPT_SECURITY_CONTEXT_CONTEXT_REQ,
            ISC_REQ_CONFIDENTIALITY, ISC_REQ_MUTUAL_AUTH, KERB_WRAP_NO_ENCRYPT,
            SECBUFFER_DATA, SECBUFFER_PADDING, SECBUFFER_STREAM, SECBUFFER_TOKEN,
            SECBUFFER_VERSION, SECPKG_ATTR_NATIVE_NAMES, SECPKG_ATTR_SIZES,
            SECPKG_CRED_ATTR_NAMES, SECPKG_CRED_INBOUND, SECPKG_CRED_OUTBOUND,
            SECURITY_NATIVE_DREP,
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
};

fn failed(res: i32) -> bool {
    res < 0
}

unsafe fn string_from_wstr(s: *mut u16) -> String {
    let slen = lstrlenW(PWSTR(s));
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
            ptr::null_mut(),
            error as u32,
            (LANG_NEUTRAL << 10) | SUBLANG_NEUTRAL,
            PWSTR(msg.as_mut_ptr()),
            (BUF - 1) as u32,
            ptr::null_mut(),
        );
    }
    unsafe { string_from_wstr(msg.as_mut_ptr()) }
}

struct Cred(SecHandle);

impl Drop for Cred {
    fn drop(&mut self) {
        unsafe {
            FreeCredentialsHandle(&mut self.0 as *mut _);
        }
    }
}

impl Cred {
    fn acquire(principal: Option<&str>, server: bool) -> Result<Cred> {
        let mut cred = SecHandle::default();
        let principal = principal.map(str_to_wstr);
        let principal_ptr =
            principal.map(|mut p| p.as_mut_ptr()).unwrap_or(ptr::null_mut());
        let mut package = str_to_wstr("Kerberos");
        let dir = if server { SECPKG_CRED_INBOUND } else { SECPKG_CRED_OUTBOUND };
        let mut lifetime = 0i64;
        let res = unsafe {
            AcquireCredentialsHandleW(
                PWSTR(principal_ptr),
                PWSTR(package.as_mut_ptr()),
                dir,
                ptr::null_mut(),
                ptr::null_mut(),
                None,
                ptr::null_mut(),
                &mut cred as *mut _,
                &mut lifetime as *mut _,
            )
        };
        if failed(res) {
            bail!("failed to acquire credentials {}", format_error(res));
        } else {
            Ok(Cred(cred))
        }
    }

    fn _name(&mut self) -> Result<String> {
        let mut names = SecPkgCredentials_NamesW::default();
        unsafe {
            let res = QueryCredentialsAttributesW(
                &mut self.0 as *mut _,
                SECPKG_CRED_ATTR_NAMES,
                &mut names as *mut _ as *mut c_void,
            );
            if failed(res) {
                bail!("failed to query cred names {}", format_error(res))
            }
            Ok(string_from_wstr(names.sUserName))
        }
    }
}

fn alloc_krb5_buf() -> Result<Vec<u8>> {
    let mut ifo = ptr::null_mut::<SecPkgInfoW>();
    let mut pkg = str_to_wstr("Kerberos");
    let res =
        unsafe { QuerySecurityPackageInfoW(PWSTR(pkg.as_mut_ptr()), &mut ifo as *mut _) };
    if failed(res) {
        if ifo != ptr::null_mut() {
            unsafe {
                FreeContextBuffer(ifo as *mut _);
            }
        }
        bail!("failed to query pkg info for Kerberos {}", format_error(res));
    }
    let max_len = unsafe { (*ifo).cbMaxToken };
    unsafe {
        FreeContextBuffer(ifo as *mut _);
    }
    let mut buf = Vec::with_capacity(max_len as usize);
    buf.extend((0..max_len).into_iter().map(|_| 0));
    Ok(buf)
}

fn query_pkg_sizes(ctx: &mut SecHandle, sz: &mut SecPkgContext_Sizes) -> Result<()> {
    let res = unsafe {
        QueryContextAttributesW(
            ctx as *mut _,
            SECPKG_ATTR_SIZES,
            sz as *mut _ as *mut c_void,
        )
    };
    if failed(res) {
        bail!("failed to query package sizes {}", format_error(res))
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
    let res = unsafe { EncryptMessage(ctx as *mut _, flags, &mut buf_desc as *mut _, 0) };
    if failed(res) {
        bail!("EncryptMessage failed {}", format_error(res))
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
    let res = unsafe {
        DecryptMessage(ctx as *mut _, &mut bufs_desc as *mut _, 0, &mut qop as *mut _)
    };
    if failed(res) {
        bail!("decrypt message failed {}", format_error(res))
    }
    let hdr_len = bufs[1].pvBuffer as usize - bufs[0].pvBuffer as usize;
    let data_len = bufs[1].cbBuffer as usize;
    msg.advance(hdr_len);
    let data = msg.split_to(data_len);
    msg.advance(len - hdr_len - data_len); // padding
    Ok(data)
}

fn convert_lifetime(expires: i64) -> Result<Duration> {
    let mut st = SYSTEMTIME::default();
    let mut lt = SYSTEMTIME::default();
    let mut ft = FILETIME::default();
    unsafe {
        GetSystemTime(&mut st as *mut _);
        if !SystemTimeToTzSpecificLocalTime(
            ptr::null_mut(),
            &st as *const _,
            &mut lt as *mut _,
        )
        .as_bool()
        {
            bail!(
                "failed to convert to local time {}",
                format_error(GetLastError().0 as i32)
            )
        }
        if !SystemTimeToFileTime(&lt as *const _, &mut ft as *mut _).as_bool() {
            bail!(
                "failed to convert current time to a filetime: {}",
                format_error(GetLastError().0 as i32)
            )
        }
        let now: u64 = ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64);
        if expires as u64 <= now {
            Ok(Duration::from_secs(0))
        } else {
            Ok(Duration::from_secs((expires as u64 - now) / 10))
        }
    }
}

#[derive(Debug)]
pub struct PendingClientCtx(ClientCtx);

impl PendingClientCtx {
    pub fn finish(mut self, token: &[u8]) -> Result<ClientCtx> {
        if self.0.do_step(Some(token))?.is_some() {
            bail!("unexpected second token")
        }
        Ok(self.0)
    }
}

pub struct ClientCtx {
    ctx: SecHandle,
    cred: Cred,
    target: Vec<u16>,
    attrs: u32,
    lifetime: i64,
    buf: Vec<u8>,
    done: bool,
    sizes: SecPkgContext_Sizes,
    header: BytesMut,
    padding: BytesMut,
}

impl Drop for ClientCtx {
    fn drop(&mut self) {
        unsafe {
            DeleteSecurityContext(&mut self.ctx as *mut _);
        }
    }
}

impl fmt::Debug for ClientCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ClientCtx")
    }
}

impl ClientCtx {
    pub fn initiate(principal: Option<&str>, target_principal: &str) -> Result<(PendingClientCtx, impl Deref<Target = [u8]>)> {
        let mut ctx = ClientCtx {
            ctx: SecHandle::default(),
            cred: Cred::acquire(principal, false)?,
            target: str_to_wstr(target_principal),
            attrs: 0,
            lifetime: 0,
            buf: alloc_krb5_buf()?,
            done: false,
            sizes: SecPkgContext_Sizes::default(),
            header: BytesMut::new(),
            padding: BytesMut::new(),
        };
        let token = ctx.do_step(None)?.ok_or_else(|| anyhow!("expected token"))?;
        Ok((PendingClientCtx(ctx), token))
    }

    fn do_step(&mut self, tok: Option<&[u8]>) -> Result<Option<BytesMut>> {
        if self.done {
            return Ok(None);
        }
        for i in 0..self.buf.len() {
            self.buf[i] = 0;
        }
        let mut out_buf = SecBuffer {
            cbBuffer: self.buf.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: self.buf.as_mut_ptr() as *mut _,
        };
        let mut out_buf_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut out_buf as *mut _,
        };
        let mut in_buf = SecBuffer {
            cbBuffer: tok.map(|t| t.len()).unwrap_or(0) as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: tok
                .map(|t| unsafe { mem::transmute::<*const u8, *mut c_void>(t.as_ptr()) })
                .unwrap_or(ptr::null_mut()),
        };
        let mut in_buf_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut in_buf as *mut _,
        };
        let ctx_ptr =
            if tok.is_none() { ptr::null_mut() } else { &mut self.ctx as *mut _ };
        let in_buf_ptr =
            if tok.is_some() { &mut in_buf_desc as *mut _ } else { ptr::null_mut() };
        let res = unsafe {
            InitializeSecurityContextW(
                &mut self.cred.0 as *mut _,
                ctx_ptr,
                self.target.as_mut_ptr(),
                ISC_REQ_CONFIDENTIALITY | ISC_REQ_MUTUAL_AUTH,
                0,
                SECURITY_NATIVE_DREP,
                in_buf_ptr,
                0,
                &mut self.ctx as *mut _,
                &mut out_buf_desc as *mut _,
                &mut self.attrs as *mut _,
                &mut self.lifetime as *mut _,
            )
        };
        if failed(res) {
            bail!("ClientCtx::step failed {}", format_error(res))
        }
        let res = res as u32;
        if res == SEC_E_OK.0 {
            query_pkg_sizes(&mut self.ctx, &mut self.sizes)?;
            self.done = true;
        }
        if res == SEC_I_COMPLETE_AND_CONTINUE.0 || res == SEC_I_COMPLETE_NEEDED.0 {
            let res = unsafe { CompleteAuthToken(ctx_ptr, &mut out_buf_desc as *mut _) };
            if failed(res) {
                bail!("complete token failed {}", format_error(res))
            }
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
        wrap(&mut self.ctx, &self.sizes, encrypt, msg)
    }

    fn wrap_iov(&mut self, encrypt: bool, mut msg: BytesMut) -> Result<Self::IOVBuffer> {
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

pub struct ServerCtx {
    ctx: SecHandle,
    cred: Cred,
    buf: Vec<u8>,
    attrs: u32,
    lifetime: i64,
    done: bool,
    sizes: SecPkgContext_Sizes,
    header: BytesMut,
    padding: BytesMut,
}

impl Drop for ServerCtx {
    fn drop(&mut self) {
        unsafe {
            DeleteSecurityContext(&mut self.ctx as *mut _);
        }
    }
}

impl fmt::Debug for ServerCtx {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ServerCtx")
    }
}

impl ServerCtx {
    pub fn accept(principal: Option<&str>, token: &[u8]) -> Result<(Self, impl Deref<Target = [u8]>)> {
        let mut ctx = ServerCtx {
            ctx: SecHandle::default(),
            cred: Cred::acquire(principal, true)?,
            buf: alloc_krb5_buf()?,
            attrs: 0,
            lifetime: 0,
            done: false,
            sizes: SecPkgContext_Sizes::default(),
            header: BytesMut::new(),
            padding: BytesMut::new(),
        };
        let token = ctx.do_step(Some(token))?.ok_or_else(|| anyhow!("expected token"))?;
        Ok((ctx, token))
    }

    fn do_step(&mut self, tok: Option<&[u8]>) -> Result<Option<BytesMut>> {
        let tok = tok.ok_or_else(|| anyhow!("no token supplied"))?;
        if self.done {
            return Ok(None);
        }
        for i in 0..self.buf.len() {
            self.buf[i] = 0;
        }
        let mut out_buf = SecBuffer {
            cbBuffer: self.buf.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: self.buf.as_mut_ptr() as *mut _,
        };
        let mut out_buf_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut out_buf as *mut _,
        };
        let mut in_buf = SecBuffer {
            cbBuffer: tok.len() as u32,
            BufferType: SECBUFFER_TOKEN,
            pvBuffer: unsafe { mem::transmute::<*const u8, *mut c_void>(tok.as_ptr()) },
        };
        let mut in_buf_desc = SecBufferDesc {
            ulVersion: SECBUFFER_VERSION,
            cBuffers: 1,
            pBuffers: &mut in_buf as *mut _,
        };
        let dfsh = SecHandle::default();
        let ctx_ptr =
            if self.ctx.dwLower == dfsh.dwLower && self.ctx.dwUpper == dfsh.dwUpper {
                ptr::null_mut()
            } else {
                &mut self.ctx as *mut _
            };
        let res = unsafe {
            AcceptSecurityContext(
                &mut self.cred.0 as *mut _,
                ctx_ptr,
                &mut in_buf_desc as *mut _,
                ACCEPT_SECURITY_CONTEXT_CONTEXT_REQ(
                    ISC_REQ_CONFIDENTIALITY | ISC_REQ_MUTUAL_AUTH,
                ),
                SECURITY_NATIVE_DREP,
                &mut self.ctx as *mut _,
                &mut out_buf_desc as *mut _,
                &mut self.attrs as *mut _,
                &mut self.lifetime as *mut _,
            )
        };
        if failed(res) {
            bail!("ServerCtx::step failed {}", format_error(res));
        }
        let res = res as u32;
        if res == SEC_E_OK.0 {
            query_pkg_sizes(&mut self.ctx, &mut self.sizes)?;
            self.done = true;
        }
        if res == SEC_I_COMPLETE_AND_CONTINUE.0 || res == SEC_I_COMPLETE_NEEDED.0 {
            let res = unsafe { CompleteAuthToken(ctx_ptr, &mut out_buf_desc as *mut _) };
            if failed(res) {
                bail!("complete token failed {}", format_error(res))
            }
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
        wrap(&mut self.ctx, &self.sizes, encrypt, msg)
    }

    fn wrap_iov(&mut self, encrypt: bool, mut msg: BytesMut) -> Result<Self::IOVBuffer> {
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

impl K5ServerCtx for ServerCtx {
    fn client(&mut self) -> Result<String> {
        let mut names = SecPkgContext_NativeNamesW::default();
        unsafe {
            let res = QueryContextAttributesW(
                &mut self.ctx as *mut _,
                SECPKG_ATTR_NATIVE_NAMES,
                &mut names as *mut _ as *mut c_void,
            );
            if failed(res) {
                bail!("failed to get client name {}", format_error(res))
            }
            Ok(string_from_wstr(names.sClientName))
        }
    }
}

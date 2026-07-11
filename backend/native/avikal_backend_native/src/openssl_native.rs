// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Atharva Sen Barai.

//! Minimal dynamically loaded OpenSSL 3 EVP bridge.
//!
//! Avikal deliberately loads its bundled libcrypto by absolute path. Keeping
//! this bridge narrow avoids temporary PEM/signature files and subprocesses
//! while retaining OpenSSL's provider-backed ML-KEM, ML-DSA, SLH-DSA, and
//! X25519 implementations and the existing PEM wire representation.

use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;
use std::ffi::{c_char, c_int, c_long, c_uchar, c_void, CStr, CString};
use std::path::{Path, PathBuf};
use std::ptr;
use std::sync::OnceLock;
use zeroize::Zeroize;

const MAX_PEM_BYTES: usize = 1024 * 1024;
const MAX_KEM_CIPHERTEXT_BYTES: usize = 64 * 1024;
const MAX_SHARED_SECRET_BYTES: usize = 4 * 1024;
const MAX_SIGNATURE_BYTES: usize = 1024 * 1024;
const MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

struct DynamicLibrary {
    handle: *mut c_void,
}

#[cfg(windows)]
#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryExW(path: *const u16, file: *mut c_void, flags: u32) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const c_char) -> *mut c_void;
    fn FreeLibrary(module: *mut c_void) -> c_int;
}

#[cfg(windows)]
const LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR: u32 = 0x0000_0100;
#[cfg(windows)]
const LOAD_LIBRARY_SEARCH_SYSTEM32: u32 = 0x0000_0800;

#[cfg(unix)]
#[link(name = "dl")]
extern "C" {
    fn dlopen(path: *const c_char, flags: c_int) -> *mut c_void;
    fn dlsym(handle: *mut c_void, name: *const c_char) -> *mut c_void;
    fn dlclose(handle: *mut c_void) -> c_int;
    fn dlerror() -> *const c_char;
}

impl DynamicLibrary {
    unsafe fn open(path: &Path) -> Result<Self, String> {
        #[cfg(windows)]
        {
            let mut wide: Vec<u16> = path.as_os_str().encode_wide().collect();
            wide.push(0);
            let handle = LoadLibraryExW(
                wide.as_ptr(),
                ptr::null_mut(),
                LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR | LOAD_LIBRARY_SEARCH_SYSTEM32,
            );
            if handle.is_null() {
                return Err(format!("Windows could not load {}", path.display()));
            }
            Ok(Self { handle })
        }
        #[cfg(unix)]
        {
            const RTLD_NOW: c_int = 2;
            use std::os::unix::ffi::OsStrExt;
            let path = CString::new(path.as_os_str().as_bytes())
                .map_err(|_| "Bundled libcrypto path contains a NUL byte".to_string())?;
            let handle = dlopen(path.as_ptr(), RTLD_NOW);
            if handle.is_null() {
                let error = dlerror();
                let detail = if error.is_null() {
                    "unknown loader error".into()
                } else {
                    CStr::from_ptr(error).to_string_lossy().into_owned()
                };
                return Err(format!("Unable to load bundled libcrypto: {detail}"));
            }
            Ok(Self { handle })
        }
    }

    unsafe fn symbol<T: Copy>(&self, name: &str) -> Result<T, String> {
        let name_c =
            CString::new(name).map_err(|_| "OpenSSL symbol name is invalid".to_string())?;
        #[cfg(windows)]
        let address = GetProcAddress(self.handle, name_c.as_ptr());
        #[cfg(unix)]
        let address = dlsym(self.handle, name_c.as_ptr());
        if address.is_null() {
            return Err(format!("Bundled OpenSSL is missing {name}"));
        }
        if std::mem::size_of::<T>() != std::mem::size_of::<*mut c_void>() {
            return Err(format!("Invalid function-pointer size for {name}"));
        }
        Ok(std::mem::transmute_copy(&address))
    }
}

impl Drop for DynamicLibrary {
    fn drop(&mut self) {
        unsafe {
            #[cfg(windows)]
            {
                FreeLibrary(self.handle);
            }
            #[cfg(unix)]
            {
                dlclose(self.handle);
            }
        }
    }
}

unsafe impl Send for DynamicLibrary {}
unsafe impl Sync for DynamicLibrary {}

enum Bio {}
enum EvpPkey {}
enum EvpPkeyCtx {}
enum EvpMdCtx {}
enum OsslProvider {}

type PemPasswordCallback =
    Option<unsafe extern "C" fn(*mut c_char, c_int, c_int, *mut c_void) -> c_int>;

struct OpenSslApi {
    _library: DynamicLibrary,
    canonical_path: PathBuf,
    provider: *mut OsslProvider,
    init_crypto: unsafe extern "C" fn(u64, *const c_void) -> c_int,
    openssl_version: unsafe extern "C" fn(c_int) -> *const c_char,
    provider_load: unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut OsslProvider,
    bio_s_mem: unsafe extern "C" fn() -> *const c_void,
    bio_new: unsafe extern "C" fn(*const c_void) -> *mut Bio,
    bio_free: unsafe extern "C" fn(*mut Bio) -> c_int,
    bio_write: unsafe extern "C" fn(*mut Bio, *const c_void, c_int) -> c_int,
    bio_read: unsafe extern "C" fn(*mut Bio, *mut c_void, c_int) -> c_int,
    bio_ctrl: unsafe extern "C" fn(*mut Bio, c_int, c_long, *mut c_void) -> c_long,
    pkey_ctx_new_from_name:
        unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut EvpPkeyCtx,
    pkey_ctx_new_from_pkey:
        unsafe extern "C" fn(*mut c_void, *mut EvpPkey, *const c_char) -> *mut EvpPkeyCtx,
    pkey_ctx_free: unsafe extern "C" fn(*mut EvpPkeyCtx),
    pkey_keygen_init: unsafe extern "C" fn(*mut EvpPkeyCtx) -> c_int,
    pkey_generate: unsafe extern "C" fn(*mut EvpPkeyCtx, *mut *mut EvpPkey) -> c_int,
    pkey_free: unsafe extern "C" fn(*mut EvpPkey),
    pem_write_private: unsafe extern "C" fn(
        *mut Bio,
        *const EvpPkey,
        *const c_void,
        *const c_uchar,
        c_int,
        PemPasswordCallback,
        *mut c_void,
    ) -> c_int,
    pem_write_public: unsafe extern "C" fn(*mut Bio, *const EvpPkey) -> c_int,
    pem_read_private: unsafe extern "C" fn(
        *mut Bio,
        *mut *mut EvpPkey,
        PemPasswordCallback,
        *mut c_void,
        *mut c_void,
        *const c_char,
    ) -> *mut EvpPkey,
    pem_read_public: unsafe extern "C" fn(
        *mut Bio,
        *mut *mut EvpPkey,
        PemPasswordCallback,
        *mut c_void,
        *mut c_void,
        *const c_char,
    ) -> *mut EvpPkey,
    encapsulate_init: unsafe extern "C" fn(*mut EvpPkeyCtx, *const c_void) -> c_int,
    encapsulate: unsafe extern "C" fn(
        *mut EvpPkeyCtx,
        *mut c_uchar,
        *mut usize,
        *mut c_uchar,
        *mut usize,
    ) -> c_int,
    decapsulate_init: unsafe extern "C" fn(*mut EvpPkeyCtx, *const c_void) -> c_int,
    decapsulate: unsafe extern "C" fn(
        *mut EvpPkeyCtx,
        *mut c_uchar,
        *mut usize,
        *const c_uchar,
        usize,
    ) -> c_int,
    derive_init: unsafe extern "C" fn(*mut EvpPkeyCtx) -> c_int,
    derive_set_peer: unsafe extern "C" fn(*mut EvpPkeyCtx, *const EvpPkey) -> c_int,
    derive: unsafe extern "C" fn(*mut EvpPkeyCtx, *mut c_uchar, *mut usize) -> c_int,
    md_ctx_new: unsafe extern "C" fn() -> *mut EvpMdCtx,
    md_ctx_free: unsafe extern "C" fn(*mut EvpMdCtx),
    digest_sign_init: unsafe extern "C" fn(
        *mut EvpMdCtx,
        *mut *mut EvpPkeyCtx,
        *const c_char,
        *mut c_void,
        *const c_char,
        *mut EvpPkey,
        *const c_void,
    ) -> c_int,
    digest_sign: unsafe extern "C" fn(
        *mut EvpMdCtx,
        *mut c_uchar,
        *mut usize,
        *const c_uchar,
        usize,
    ) -> c_int,
    digest_verify_init: unsafe extern "C" fn(
        *mut EvpMdCtx,
        *mut *mut EvpPkeyCtx,
        *const c_char,
        *mut c_void,
        *const c_char,
        *mut EvpPkey,
        *const c_void,
    ) -> c_int,
    digest_verify:
        unsafe extern "C" fn(*mut EvpMdCtx, *const c_uchar, usize, *const c_uchar, usize) -> c_int,
    err_get_error: unsafe extern "C" fn() -> u64,
    err_error_string_n: unsafe extern "C" fn(u64, *mut c_char, usize),
}

// The loaded OpenSSL library is process-global and immutable after setup.
unsafe impl Send for OpenSslApi {}
unsafe impl Sync for OpenSslApi {}

static OPENSSL: OnceLock<Result<OpenSslApi, String>> = OnceLock::new();

macro_rules! load_symbol {
    ($library:expr, $name:literal, $ty:ty) => {{
        $library.symbol::<$ty>($name)?
    }};
}

impl OpenSslApi {
    unsafe fn load(path: &Path) -> Result<Self, String> {
        let canonical_path = path
            .canonicalize()
            .map_err(|error| format!("Unable to resolve bundled libcrypto: {error}"))?;
        let library = DynamicLibrary::open(&canonical_path)?;
        let mut api = Self {
            init_crypto: load_symbol!(
                library,
                "OPENSSL_init_crypto",
                unsafe extern "C" fn(u64, *const c_void) -> c_int
            ),
            openssl_version: load_symbol!(
                library,
                "OpenSSL_version",
                unsafe extern "C" fn(c_int) -> *const c_char
            ),
            provider_load: load_symbol!(
                library,
                "OSSL_PROVIDER_load",
                unsafe extern "C" fn(*mut c_void, *const c_char) -> *mut OsslProvider
            ),
            bio_s_mem: load_symbol!(
                library,
                "BIO_s_mem",
                unsafe extern "C" fn() -> *const c_void
            ),
            bio_new: load_symbol!(
                library,
                "BIO_new",
                unsafe extern "C" fn(*const c_void) -> *mut Bio
            ),
            bio_free: load_symbol!(library, "BIO_free", unsafe extern "C" fn(*mut Bio) -> c_int),
            bio_write: load_symbol!(
                library,
                "BIO_write",
                unsafe extern "C" fn(*mut Bio, *const c_void, c_int) -> c_int
            ),
            bio_read: load_symbol!(
                library,
                "BIO_read",
                unsafe extern "C" fn(*mut Bio, *mut c_void, c_int) -> c_int
            ),
            bio_ctrl: load_symbol!(
                library,
                "BIO_ctrl",
                unsafe extern "C" fn(*mut Bio, c_int, c_long, *mut c_void) -> c_long
            ),
            pkey_ctx_new_from_name: load_symbol!(
                library,
                "EVP_PKEY_CTX_new_from_name",
                unsafe extern "C" fn(*mut c_void, *const c_char, *const c_char) -> *mut EvpPkeyCtx
            ),
            pkey_ctx_new_from_pkey: load_symbol!(
                library,
                "EVP_PKEY_CTX_new_from_pkey",
                unsafe extern "C" fn(*mut c_void, *mut EvpPkey, *const c_char) -> *mut EvpPkeyCtx
            ),
            pkey_ctx_free: load_symbol!(
                library,
                "EVP_PKEY_CTX_free",
                unsafe extern "C" fn(*mut EvpPkeyCtx)
            ),
            pkey_keygen_init: load_symbol!(
                library,
                "EVP_PKEY_keygen_init",
                unsafe extern "C" fn(*mut EvpPkeyCtx) -> c_int
            ),
            pkey_generate: load_symbol!(
                library,
                "EVP_PKEY_generate",
                unsafe extern "C" fn(*mut EvpPkeyCtx, *mut *mut EvpPkey) -> c_int
            ),
            pkey_free: load_symbol!(library, "EVP_PKEY_free", unsafe extern "C" fn(*mut EvpPkey)),
            pem_write_private: load_symbol!(
                library,
                "PEM_write_bio_PrivateKey",
                unsafe extern "C" fn(
                    *mut Bio,
                    *const EvpPkey,
                    *const c_void,
                    *const c_uchar,
                    c_int,
                    PemPasswordCallback,
                    *mut c_void,
                ) -> c_int
            ),
            pem_write_public: load_symbol!(
                library,
                "PEM_write_bio_PUBKEY",
                unsafe extern "C" fn(*mut Bio, *const EvpPkey) -> c_int
            ),
            pem_read_private: load_symbol!(
                library,
                "PEM_read_bio_PrivateKey_ex",
                unsafe extern "C" fn(
                    *mut Bio,
                    *mut *mut EvpPkey,
                    PemPasswordCallback,
                    *mut c_void,
                    *mut c_void,
                    *const c_char,
                ) -> *mut EvpPkey
            ),
            pem_read_public: load_symbol!(
                library,
                "PEM_read_bio_PUBKEY_ex",
                unsafe extern "C" fn(
                    *mut Bio,
                    *mut *mut EvpPkey,
                    PemPasswordCallback,
                    *mut c_void,
                    *mut c_void,
                    *const c_char,
                ) -> *mut EvpPkey
            ),
            encapsulate_init: load_symbol!(
                library,
                "EVP_PKEY_encapsulate_init",
                unsafe extern "C" fn(*mut EvpPkeyCtx, *const c_void) -> c_int
            ),
            encapsulate: load_symbol!(
                library,
                "EVP_PKEY_encapsulate",
                unsafe extern "C" fn(
                    *mut EvpPkeyCtx,
                    *mut c_uchar,
                    *mut usize,
                    *mut c_uchar,
                    *mut usize,
                ) -> c_int
            ),
            decapsulate_init: load_symbol!(
                library,
                "EVP_PKEY_decapsulate_init",
                unsafe extern "C" fn(*mut EvpPkeyCtx, *const c_void) -> c_int
            ),
            decapsulate: load_symbol!(
                library,
                "EVP_PKEY_decapsulate",
                unsafe extern "C" fn(
                    *mut EvpPkeyCtx,
                    *mut c_uchar,
                    *mut usize,
                    *const c_uchar,
                    usize,
                ) -> c_int
            ),
            derive_init: load_symbol!(
                library,
                "EVP_PKEY_derive_init",
                unsafe extern "C" fn(*mut EvpPkeyCtx) -> c_int
            ),
            derive_set_peer: load_symbol!(
                library,
                "EVP_PKEY_derive_set_peer",
                unsafe extern "C" fn(*mut EvpPkeyCtx, *const EvpPkey) -> c_int
            ),
            derive: load_symbol!(
                library,
                "EVP_PKEY_derive",
                unsafe extern "C" fn(*mut EvpPkeyCtx, *mut c_uchar, *mut usize) -> c_int
            ),
            md_ctx_new: load_symbol!(
                library,
                "EVP_MD_CTX_new",
                unsafe extern "C" fn() -> *mut EvpMdCtx
            ),
            md_ctx_free: load_symbol!(
                library,
                "EVP_MD_CTX_free",
                unsafe extern "C" fn(*mut EvpMdCtx)
            ),
            digest_sign_init: load_symbol!(
                library,
                "EVP_DigestSignInit_ex",
                unsafe extern "C" fn(
                    *mut EvpMdCtx,
                    *mut *mut EvpPkeyCtx,
                    *const c_char,
                    *mut c_void,
                    *const c_char,
                    *mut EvpPkey,
                    *const c_void,
                ) -> c_int
            ),
            digest_sign: load_symbol!(
                library,
                "EVP_DigestSign",
                unsafe extern "C" fn(
                    *mut EvpMdCtx,
                    *mut c_uchar,
                    *mut usize,
                    *const c_uchar,
                    usize,
                ) -> c_int
            ),
            digest_verify_init: load_symbol!(
                library,
                "EVP_DigestVerifyInit_ex",
                unsafe extern "C" fn(
                    *mut EvpMdCtx,
                    *mut *mut EvpPkeyCtx,
                    *const c_char,
                    *mut c_void,
                    *const c_char,
                    *mut EvpPkey,
                    *const c_void,
                ) -> c_int
            ),
            digest_verify: load_symbol!(
                library,
                "EVP_DigestVerify",
                unsafe extern "C" fn(
                    *mut EvpMdCtx,
                    *const c_uchar,
                    usize,
                    *const c_uchar,
                    usize,
                ) -> c_int
            ),
            err_get_error: load_symbol!(library, "ERR_get_error", unsafe extern "C" fn() -> u64),
            err_error_string_n: load_symbol!(
                library,
                "ERR_error_string_n",
                unsafe extern "C" fn(u64, *mut c_char, usize)
            ),
            _library: library,
            canonical_path,
            provider: ptr::null_mut(),
        };
        const OPENSSL_INIT_NO_LOAD_CONFIG: u64 = 0x0000_0080;
        if (api.init_crypto)(OPENSSL_INIT_NO_LOAD_CONFIG, ptr::null()) != 1 {
            return Err(
                api.error_message("Unable to initialize OpenSSL without external configuration")
            );
        }
        let default_provider =
            CString::new("default").map_err(|_| "OpenSSL provider name is invalid".to_string())?;
        api.provider = (api.provider_load)(ptr::null_mut(), default_provider.as_ptr());
        if api.provider.is_null() {
            return Err(api.error_message("Unable to load the OpenSSL default provider"));
        }
        Ok(api)
    }

    fn error_message(&self, prefix: &str) -> String {
        unsafe {
            let code = (self.err_get_error)();
            if code == 0 {
                return prefix.to_string();
            }
            let mut buffer = [0i8; 256];
            (self.err_error_string_n)(code, buffer.as_mut_ptr(), buffer.len());
            format!(
                "{prefix}: {}",
                CStr::from_ptr(buffer.as_ptr()).to_string_lossy()
            )
        }
    }

    unsafe fn new_mem_bio(&self, data: Option<&[u8]>) -> Result<*mut Bio, String> {
        let bio = (self.bio_new)((self.bio_s_mem)());
        if bio.is_null() {
            return Err(self.error_message("Unable to allocate OpenSSL memory BIO"));
        }
        if let Some(value) = data {
            if value.len() > c_int::MAX as usize
                || (self.bio_write)(bio, value.as_ptr().cast(), value.len() as c_int)
                    != value.len() as c_int
            {
                (self.bio_free)(bio);
                return Err(self.error_message("Unable to load OpenSSL key document"));
            }
        }
        Ok(bio)
    }

    unsafe fn bio_bytes(&self, bio: *mut Bio) -> Result<Vec<u8>, String> {
        const BIO_CTRL_PENDING: c_int = 10;
        let pending = (self.bio_ctrl)(bio, BIO_CTRL_PENDING, 0, ptr::null_mut());
        if pending <= 0 || pending > MAX_PEM_BYTES as c_long {
            return Err(self.error_message("OpenSSL produced an empty key document"));
        }
        let mut output = vec![0u8; pending as usize];
        let read = (self.bio_read)(bio, output.as_mut_ptr().cast(), pending as c_int);
        if read != pending as c_int {
            return Err(self.error_message("Unable to read OpenSSL key document"));
        }
        Ok(output)
    }

    unsafe fn read_key(&self, pem: &[u8], private: bool) -> Result<*mut EvpPkey, String> {
        if pem.is_empty() || pem.len() > MAX_PEM_BYTES {
            return Err("OpenSSL key document size is invalid".to_string());
        }
        let bio = self.new_mem_bio(Some(pem))?;
        let key = if private {
            (self.pem_read_private)(
                bio,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
            )
        } else {
            (self.pem_read_public)(
                bio,
                ptr::null_mut(),
                None,
                ptr::null_mut(),
                ptr::null_mut(),
                ptr::null(),
            )
        };
        (self.bio_free)(bio);
        if key.is_null() {
            Err(self.error_message("Unable to parse OpenSSL key document"))
        } else {
            Ok(key)
        }
    }
}

fn api(path: &str) -> PyResult<&'static OpenSslApi> {
    let requested = Path::new(path).canonicalize().map_err(|error| {
        PyValueError::new_err(format!("Bundled libcrypto path is invalid: {error}"))
    })?;
    let result = OPENSSL.get_or_init(|| unsafe { OpenSslApi::load(&requested) });
    match result {
        Ok(api) if api.canonical_path == requested => Ok(api),
        Ok(_) => Err(PyRuntimeError::new_err(
            "Bundled OpenSSL runtime path changed after initialization",
        )),
        Err(message) => Err(PyRuntimeError::new_err(message.clone())),
    }
}

fn py_runtime_error(api: &OpenSslApi, context: &str) -> PyErr {
    PyRuntimeError::new_err(api.error_message(context))
}

#[pyfunction]
pub fn openssl_runtime_version(library_path: &str) -> PyResult<String> {
    let api = api(library_path)?;
    unsafe {
        let value = (api.openssl_version)(0);
        if value.is_null() {
            return Err(py_runtime_error(api, "Unable to query OpenSSL version"));
        }
        Ok(CStr::from_ptr(value).to_string_lossy().into_owned())
    }
}

#[pyfunction]
pub fn openssl_generate_keypair(library_path: &str, algorithm: &str) -> PyResult<(String, String)> {
    let api = api(library_path)?;
    if !matches!(
        algorithm,
        "X25519"
            | "ML-KEM-768"
            | "ML-KEM-1024"
            | "ML-DSA-65"
            | "ML-DSA-87"
            | "SLH-DSA-SHA2-128s"
            | "SLH-DSA-SHA2-192s"
            | "SLH-DSA-SHA2-256s"
    ) {
        return Err(PyValueError::new_err(
            "Unsupported Avikal OpenSSL key algorithm",
        ));
    }
    let algorithm = CString::new(algorithm)
        .map_err(|_| PyValueError::new_err("OpenSSL algorithm name is invalid"))?;
    unsafe {
        let ctx = (api.pkey_ctx_new_from_name)(ptr::null_mut(), algorithm.as_ptr(), ptr::null());
        if ctx.is_null() {
            return Err(py_runtime_error(
                api,
                "OpenSSL does not provide the requested key algorithm",
            ));
        }
        let mut key = ptr::null_mut();
        let ok = (api.pkey_keygen_init)(ctx) == 1 && (api.pkey_generate)(ctx, &mut key) == 1;
        (api.pkey_ctx_free)(ctx);
        if !ok || key.is_null() {
            return Err(py_runtime_error(api, "OpenSSL key generation failed"));
        }
        let private_bio = match api.new_mem_bio(None) {
            Ok(bio) => bio,
            Err(error) => {
                (api.pkey_free)(key);
                return Err(PyRuntimeError::new_err(error));
            }
        };
        let public_bio = match api.new_mem_bio(None) {
            Ok(bio) => bio,
            Err(error) => {
                (api.bio_free)(private_bio);
                (api.pkey_free)(key);
                return Err(PyRuntimeError::new_err(error));
            }
        };
        let write_ok = (api.pem_write_private)(
            private_bio,
            key,
            ptr::null(),
            ptr::null(),
            0,
            None,
            ptr::null_mut(),
        ) == 1
            && (api.pem_write_public)(public_bio, key) == 1;
        let private = if write_ok {
            api.bio_bytes(private_bio)
        } else {
            Err(api.error_message("OpenSSL key serialization failed"))
        };
        let public = if write_ok {
            api.bio_bytes(public_bio)
        } else {
            Err(api.error_message("OpenSSL key serialization failed"))
        };
        (api.bio_free)(private_bio);
        (api.bio_free)(public_bio);
        (api.pkey_free)(key);
        let private = String::from_utf8(private.map_err(PyRuntimeError::new_err)?)
            .map_err(|_| PyRuntimeError::new_err("OpenSSL private key PEM is not UTF-8"))?;
        let public = String::from_utf8(public.map_err(PyRuntimeError::new_err)?)
            .map_err(|_| PyRuntimeError::new_err("OpenSSL public key PEM is not UTF-8"))?;
        Ok((private, public))
    }
}

#[pyfunction]
pub fn openssl_kem_encapsulate<'py>(
    py: Python<'py>,
    library_path: &str,
    public_pem: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let api = api(library_path)?;
    unsafe {
        let key = api
            .read_key(public_pem, false)
            .map_err(PyRuntimeError::new_err)?;
        let ctx = (api.pkey_ctx_new_from_pkey)(ptr::null_mut(), key, ptr::null());
        if ctx.is_null() || (api.encapsulate_init)(ctx, ptr::null()) != 1 {
            if !ctx.is_null() {
                (api.pkey_ctx_free)(ctx);
            }
            (api.pkey_free)(key);
            return Err(py_runtime_error(api, "OpenSSL KEM initialization failed"));
        }
        let mut ciphertext_len = 0usize;
        let mut secret_len = 0usize;
        if (api.encapsulate)(
            ctx,
            ptr::null_mut(),
            &mut ciphertext_len,
            ptr::null_mut(),
            &mut secret_len,
        ) != 1
            || ciphertext_len == 0
            || ciphertext_len > MAX_KEM_CIPHERTEXT_BYTES
            || secret_len == 0
            || secret_len > MAX_SHARED_SECRET_BYTES
        {
            (api.pkey_ctx_free)(ctx);
            (api.pkey_free)(key);
            return Err(py_runtime_error(api, "OpenSSL KEM size query failed"));
        }
        let mut ciphertext = vec![0u8; ciphertext_len];
        let mut secret = vec![0u8; secret_len];
        let ok = (api.encapsulate)(
            ctx,
            ciphertext.as_mut_ptr(),
            &mut ciphertext_len,
            secret.as_mut_ptr(),
            &mut secret_len,
        ) == 1;
        (api.pkey_ctx_free)(ctx);
        (api.pkey_free)(key);
        if !ok {
            secret.zeroize();
            return Err(py_runtime_error(api, "OpenSSL KEM encapsulation failed"));
        }
        if ciphertext_len > ciphertext.len() || secret_len > secret.len() {
            secret.zeroize();
            return Err(PyRuntimeError::new_err(
                "OpenSSL KEM returned an invalid output length",
            ));
        }
        ciphertext.truncate(ciphertext_len);
        secret.truncate(secret_len);
        let result = (PyBytes::new(py, &ciphertext), PyBytes::new(py, &secret));
        secret.zeroize();
        Ok(result)
    }
}

#[pyfunction]
pub fn openssl_kem_decapsulate<'py>(
    py: Python<'py>,
    library_path: &str,
    private_pem: &[u8],
    ciphertext: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let api = api(library_path)?;
    if ciphertext.is_empty() || ciphertext.len() > MAX_KEM_CIPHERTEXT_BYTES {
        return Err(PyValueError::new_err(
            "OpenSSL KEM ciphertext size is invalid",
        ));
    }
    unsafe {
        let key = api
            .read_key(private_pem, true)
            .map_err(PyRuntimeError::new_err)?;
        let ctx = (api.pkey_ctx_new_from_pkey)(ptr::null_mut(), key, ptr::null());
        if ctx.is_null() || (api.decapsulate_init)(ctx, ptr::null()) != 1 {
            if !ctx.is_null() {
                (api.pkey_ctx_free)(ctx);
            }
            (api.pkey_free)(key);
            return Err(py_runtime_error(api, "OpenSSL KEM initialization failed"));
        }
        let mut secret_len = 0usize;
        if (api.decapsulate)(
            ctx,
            ptr::null_mut(),
            &mut secret_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
        ) != 1
            || secret_len == 0
            || secret_len > MAX_SHARED_SECRET_BYTES
        {
            (api.pkey_ctx_free)(ctx);
            (api.pkey_free)(key);
            return Err(py_runtime_error(api, "OpenSSL KEM size query failed"));
        }
        let mut secret = vec![0u8; secret_len];
        let ok = (api.decapsulate)(
            ctx,
            secret.as_mut_ptr(),
            &mut secret_len,
            ciphertext.as_ptr(),
            ciphertext.len(),
        ) == 1;
        (api.pkey_ctx_free)(ctx);
        (api.pkey_free)(key);
        if !ok {
            secret.zeroize();
            return Err(py_runtime_error(api, "OpenSSL KEM decapsulation failed"));
        }
        if secret_len > secret.len() {
            secret.zeroize();
            return Err(PyRuntimeError::new_err(
                "OpenSSL KEM returned an invalid shared-secret length",
            ));
        }
        secret.truncate(secret_len);
        let result = PyBytes::new(py, &secret);
        secret.zeroize();
        Ok(result)
    }
}

#[pyfunction]
pub fn openssl_derive_secret<'py>(
    py: Python<'py>,
    library_path: &str,
    private_pem: &[u8],
    peer_public_pem: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let api = api(library_path)?;
    unsafe {
        let private = api
            .read_key(private_pem, true)
            .map_err(PyRuntimeError::new_err)?;
        let peer = match api.read_key(peer_public_pem, false) {
            Ok(key) => key,
            Err(error) => {
                (api.pkey_free)(private);
                return Err(PyRuntimeError::new_err(error));
            }
        };
        let ctx = (api.pkey_ctx_new_from_pkey)(ptr::null_mut(), private, ptr::null());
        let initialized =
            !ctx.is_null() && (api.derive_init)(ctx) == 1 && (api.derive_set_peer)(ctx, peer) == 1;
        if !initialized {
            if !ctx.is_null() {
                (api.pkey_ctx_free)(ctx);
            }
            (api.pkey_free)(private);
            (api.pkey_free)(peer);
            return Err(py_runtime_error(
                api,
                "OpenSSL key agreement initialization failed",
            ));
        }
        let mut length = 0usize;
        if (api.derive)(ctx, ptr::null_mut(), &mut length) != 1
            || length == 0
            || length > MAX_SHARED_SECRET_BYTES
        {
            (api.pkey_ctx_free)(ctx);
            (api.pkey_free)(private);
            (api.pkey_free)(peer);
            return Err(py_runtime_error(
                api,
                "OpenSSL key agreement size query failed",
            ));
        }
        let mut secret = vec![0u8; length];
        let ok = (api.derive)(ctx, secret.as_mut_ptr(), &mut length) == 1;
        (api.pkey_ctx_free)(ctx);
        (api.pkey_free)(private);
        (api.pkey_free)(peer);
        if !ok {
            secret.zeroize();
            return Err(py_runtime_error(api, "OpenSSL key agreement failed"));
        }
        if length > secret.len() {
            secret.zeroize();
            return Err(PyRuntimeError::new_err(
                "OpenSSL key agreement returned an invalid length",
            ));
        }
        secret.truncate(length);
        let result = PyBytes::new(py, &secret);
        secret.zeroize();
        Ok(result)
    }
}

#[pyfunction]
pub fn openssl_sign_message<'py>(
    py: Python<'py>,
    library_path: &str,
    private_pem: &[u8],
    message: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let api = api(library_path)?;
    if message.is_empty() || message.len() > MAX_MESSAGE_BYTES {
        return Err(PyValueError::new_err(
            "OpenSSL signing message size is invalid",
        ));
    }
    unsafe {
        let key = api
            .read_key(private_pem, true)
            .map_err(PyRuntimeError::new_err)?;
        let ctx = (api.md_ctx_new)();
        if ctx.is_null()
            || (api.digest_sign_init)(
                ctx,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                key,
                ptr::null(),
            ) != 1
        {
            if !ctx.is_null() {
                (api.md_ctx_free)(ctx);
            }
            (api.pkey_free)(key);
            return Err(py_runtime_error(
                api,
                "OpenSSL signature initialization failed",
            ));
        }
        let mut length = 0usize;
        if (api.digest_sign)(
            ctx,
            ptr::null_mut(),
            &mut length,
            message.as_ptr(),
            message.len(),
        ) != 1
            || length == 0
            || length > MAX_SIGNATURE_BYTES
        {
            (api.md_ctx_free)(ctx);
            (api.pkey_free)(key);
            return Err(py_runtime_error(api, "OpenSSL signature size query failed"));
        }
        let mut signature = vec![0u8; length];
        let ok = (api.digest_sign)(
            ctx,
            signature.as_mut_ptr(),
            &mut length,
            message.as_ptr(),
            message.len(),
        ) == 1;
        (api.md_ctx_free)(ctx);
        (api.pkey_free)(key);
        if !ok {
            return Err(py_runtime_error(api, "OpenSSL signing failed"));
        }
        if length > signature.len() {
            return Err(PyRuntimeError::new_err(
                "OpenSSL signing returned an invalid signature length",
            ));
        }
        signature.truncate(length);
        Ok(PyBytes::new(py, &signature))
    }
}

#[pyfunction]
pub fn openssl_verify_signature(
    library_path: &str,
    public_pem: &[u8],
    message: &[u8],
    signature: &[u8],
) -> PyResult<bool> {
    let api = api(library_path)?;
    if message.is_empty() || message.len() > MAX_MESSAGE_BYTES {
        return Err(PyValueError::new_err(
            "OpenSSL verification message size is invalid",
        ));
    }
    if signature.is_empty() || signature.len() > MAX_SIGNATURE_BYTES {
        return Err(PyValueError::new_err("OpenSSL signature size is invalid"));
    }
    unsafe {
        let key = api
            .read_key(public_pem, false)
            .map_err(PyRuntimeError::new_err)?;
        let ctx = (api.md_ctx_new)();
        if ctx.is_null()
            || (api.digest_verify_init)(
                ctx,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null(),
                key,
                ptr::null(),
            ) != 1
        {
            if !ctx.is_null() {
                (api.md_ctx_free)(ctx);
            }
            (api.pkey_free)(key);
            return Err(py_runtime_error(
                api,
                "OpenSSL verification initialization failed",
            ));
        }
        let result = (api.digest_verify)(
            ctx,
            signature.as_ptr(),
            signature.len(),
            message.as_ptr(),
            message.len(),
        );
        (api.md_ctx_free)(ctx);
        (api.pkey_free)(key);
        match result {
            1 => Ok(true),
            0 => Ok(false),
            _ => Err(py_runtime_error(
                api,
                "OpenSSL signature verification failed",
            )),
        }
    }
}

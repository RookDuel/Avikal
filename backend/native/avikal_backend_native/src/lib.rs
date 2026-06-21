// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Atharva Sen Barai.

// PyO3's Python boundary macro expansion currently trips this lint on valid
// Result-returning bindings. Keep clippy strict for the rest of the crate.
#![allow(clippy::useless_conversion)]

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use aes_gcm_stream::{Aes256GcmStreamDecryptor, Aes256GcmStreamEncryptor};
use argon2::{Algorithm, Argon2, Params, Version};
use flate2::{Compress, Compression, Decompress, FlushCompress, FlushDecompress, Status};
use hkdf::Hkdf;
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyModule};
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::{Digest as Sha2Digest, Sha256};
use sha3::Sha3_256;
use zeroize::{Zeroize, Zeroizing};

mod chess_codec;

const AES256_KEY_BYTES: usize = 32;
const AESGCM_NONCE_BYTES: usize = 12;
const AESGCM_TAG_BYTES: usize = 16;
const DEFAULT_NATIVE_DECOMPRESS_LIMIT: u64 = 32 * 1024 * 1024 * 1024;
const AVP_CHUNK_AAD_LABEL: &[u8] = b"avikal-payload-chunk";
const AVP_CHUNK_HEADER_BYTES: usize = 16;
const AVP_MAX_CHUNK_BYTES: usize = 64 * 1024 * 1024;

type EncoderFinalizeResult = (Py<PyBytes>, Option<Py<PyBytes>>, Py<PyBytes>, u64, u64);

fn value_error(message: impl Into<String>) -> PyErr {
    PyValueError::new_err(message.into())
}

fn runtime_error(message: impl Into<String>) -> PyErr {
    PyRuntimeError::new_err(message.into())
}

fn validate_required_bytes(name: &str, value: &[u8]) -> PyResult<()> {
    if value.is_empty() {
        return Err(value_error(format!("{name} must not be empty")));
    }
    Ok(())
}

fn validate_len(name: &str, value: &[u8], expected_len: usize) -> PyResult<()> {
    if value.len() != expected_len {
        return Err(value_error(format!("{name} must be {expected_len} bytes")));
    }
    Ok(())
}

fn copy_key32(key: &[u8], field_name: &str) -> PyResult<[u8; AES256_KEY_BYTES]> {
    validate_len(field_name, key, AES256_KEY_BYTES)?;
    let mut copied = [0u8; AES256_KEY_BYTES];
    copied.copy_from_slice(key);
    Ok(copied)
}

fn copy_tag16(tag: &[u8], field_name: &str) -> PyResult<[u8; AESGCM_TAG_BYTES]> {
    validate_len(field_name, tag, AESGCM_TAG_BYTES)?;
    let mut copied = [0u8; AESGCM_TAG_BYTES];
    copied.copy_from_slice(tag);
    Ok(copied)
}

fn hkdf_sha256_impl(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> PyResult<Vec<u8>> {
    validate_required_bytes("IKM", ikm)?;
    if length == 0 {
        return Err(value_error(
            "Requested HKDF output length must be greater than zero",
        ));
    }

    let hkdf = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut output = Zeroizing::new(vec![0u8; length]);
    hkdf.expand(info, &mut output)
        .map_err(|_| value_error("Requested HKDF output length is invalid"))?;
    Ok(output.to_vec())
}

fn hkdf_sha3_256_impl(
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    length: usize,
) -> PyResult<Vec<u8>> {
    validate_required_bytes("IKM", ikm)?;
    if length == 0 {
        return Err(value_error(
            "Requested HKDF output length must be greater than zero",
        ));
    }

    let hkdf = Hkdf::<Sha3_256>::new(salt, ikm);
    let mut output = Zeroizing::new(vec![0u8; length]);
    hkdf.expand(info, &mut output)
        .map_err(|_| value_error("Requested HKDF output length is invalid"))?;
    Ok(output.to_vec())
}

fn aes256gcm_encrypt_impl(
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> PyResult<Vec<u8>> {
    validate_len("key", key, AES256_KEY_BYTES)?;
    validate_len("nonce", nonce, AESGCM_NONCE_BYTES)?;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| value_error("key must be 32 bytes"))?;
    let nonce = Nonce::from_slice(nonce);
    let mut buffer = plaintext.to_vec();
    cipher
        .encrypt_in_place(nonce, aad, &mut buffer)
        .map_err(|_| value_error("AES-GCM encryption failed"))?;
    let output = buffer.clone();
    buffer.zeroize();
    Ok(output)
}

fn aes256gcm_decrypt_impl(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> PyResult<Vec<u8>> {
    validate_len("key", key, AES256_KEY_BYTES)?;
    validate_len("nonce", nonce, AESGCM_NONCE_BYTES)?;

    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| value_error("key must be 32 bytes"))?;
    let nonce = Nonce::from_slice(nonce);
    let mut buffer = ciphertext.to_vec();
    cipher
        .decrypt_in_place(nonce, aad, &mut buffer)
        .map_err(|_| value_error("AES-GCM decryption failed"))?;
    let output = buffer.clone();
    buffer.zeroize();
    Ok(output)
}

fn avp_chunk_nonce(base_nonce: &[u8], chunk_index: u64) -> PyResult<[u8; AESGCM_NONCE_BYTES]> {
    validate_len("base_nonce", base_nonce, AESGCM_NONCE_BYTES)?;
    if chunk_index > u32::MAX as u64 {
        return Err(value_error("AVP chunk index is out of bounds"));
    }
    let mut nonce = [0u8; AESGCM_NONCE_BYTES];
    nonce[..8].copy_from_slice(&base_nonce[..8]);
    nonce[8..].copy_from_slice(&(chunk_index as u32).to_be_bytes());
    Ok(nonce)
}

fn avp_chunk_header(
    chunk_index: u64,
    original_len: usize,
    data_len: usize,
) -> PyResult<[u8; AVP_CHUNK_HEADER_BYTES]> {
    if original_len > AVP_MAX_CHUNK_BYTES {
        return Err(value_error("AVP chunk size is out of bounds"));
    }
    if data_len == 0 || data_len > AVP_MAX_CHUNK_BYTES + 1024 + AESGCM_TAG_BYTES {
        return Err(value_error("AVP chunk data size is out of bounds"));
    }
    let mut header = [0u8; AVP_CHUNK_HEADER_BYTES];
    header[..8].copy_from_slice(&chunk_index.to_be_bytes());
    header[8..12].copy_from_slice(&(original_len as u32).to_be_bytes());
    header[12..16].copy_from_slice(&(data_len as u32).to_be_bytes());
    Ok(header)
}

fn avp_chunk_aad(archive_aad: &[u8], payload_header: &[u8], chunk_header: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(
        archive_aad.len() + AVP_CHUNK_AAD_LABEL.len() + payload_header.len() + chunk_header.len(),
    );
    aad.extend_from_slice(archive_aad);
    aad.extend_from_slice(AVP_CHUNK_AAD_LABEL);
    aad.extend_from_slice(payload_header);
    aad.extend_from_slice(chunk_header);
    aad
}

fn compress_chunk(input: &[u8]) -> PyResult<Vec<u8>> {
    let mut compressor = Compress::new(Compression::fast(), true);
    compress_all(&mut compressor, input, FlushCompress::Finish)
}

fn decompress_chunk(input: &[u8]) -> PyResult<Vec<u8>> {
    let mut decompressor = Decompress::new(true);
    decompress_all(&mut decompressor, input, FlushDecompress::Finish)
}

fn reserve_output_capacity(output: &mut Vec<u8>, hint: usize) {
    let required = hint.max(4096);
    if output.capacity().saturating_sub(output.len()) < required {
        output.reserve(required);
    }
}

fn compress_all(
    compressor: &mut Compress,
    input: &[u8],
    flush: FlushCompress,
) -> PyResult<Vec<u8>> {
    let mut output = Vec::new();
    reserve_output_capacity(&mut output, input.len().saturating_add(256));
    let mut offset = 0usize;
    let mut spins_without_progress = 0u8;

    loop {
        let before_in = compressor.total_in();
        let before_out = compressor.total_out();
        let status = compressor
            .compress_vec(&input[offset..], &mut output, flush)
            .map_err(|exc| runtime_error(format!("Payload compression failed: {exc}")))?;
        let consumed = (compressor.total_in() - before_in) as usize;
        let produced = (compressor.total_out() - before_out) as usize;
        offset += consumed;

        if status == Status::StreamEnd {
            break;
        }
        if offset >= input.len() && flush == FlushCompress::None {
            break;
        }

        if consumed == 0 && produced == 0 {
            spins_without_progress = spins_without_progress.saturating_add(1);
            if spins_without_progress > 4 {
                return Err(runtime_error("Payload compression stalled unexpectedly"));
            }
        } else {
            spins_without_progress = 0;
        }

        reserve_output_capacity(
            &mut output,
            input.len().saturating_sub(offset).saturating_add(256),
        );
    }

    Ok(output)
}

fn decompress_all(
    decompressor: &mut Decompress,
    input: &[u8],
    flush: FlushDecompress,
) -> PyResult<Vec<u8>> {
    let mut output = Vec::new();
    reserve_output_capacity(
        &mut output,
        input.len().saturating_mul(2).saturating_add(4096),
    );
    let mut offset = 0usize;
    let mut spins_without_progress = 0u8;

    loop {
        let before_in = decompressor.total_in();
        let before_out = decompressor.total_out();
        let status = decompressor
            .decompress_vec(&input[offset..], &mut output, flush)
            .map_err(|exc| runtime_error(format!("Payload decompression failed: {exc}")))?;
        let consumed = (decompressor.total_in() - before_in) as usize;
        let produced = (decompressor.total_out() - before_out) as usize;
        offset += consumed;

        if status == Status::StreamEnd {
            break;
        }
        if offset >= input.len() && flush == FlushDecompress::None {
            break;
        }

        if consumed == 0 && produced == 0 {
            spins_without_progress = spins_without_progress.saturating_add(1);
            if spins_without_progress > 4 {
                return Err(runtime_error("Payload decompression stalled unexpectedly"));
            }
        } else {
            spins_without_progress = 0;
        }

        reserve_output_capacity(
            &mut output,
            input.len().saturating_mul(2).saturating_add(4096),
        );
    }

    Ok(output)
}

#[pyclass(module = "avikal_backend._native")]
struct PayloadStreamEncoder {
    compressor: Compress,
    encryptor: Option<Aes256GcmStreamEncryptor>,
    checksum: Sha256,
    original_size: u64,
    compressed_size: u64,
    finished: bool,
}

#[pymethods]
impl PayloadStreamEncoder {
    #[new]
    #[pyo3(signature = (encrypt_key=None, nonce=None, aad=None, *, compression_level=6))]
    fn new(
        encrypt_key: Option<&[u8]>,
        nonce: Option<&[u8]>,
        aad: Option<&[u8]>,
        compression_level: u32,
    ) -> PyResult<Self> {
        if compression_level > 9 {
            return Err(value_error("compression_level must be between 0 and 9"));
        }
        let aad = aad.unwrap_or(&[]);

        let mut encryptor = None;
        if let Some(key_bytes) = encrypt_key {
            let mut key = copy_key32(key_bytes, "encrypt_key")?;
            let resolved_nonce = nonce
                .ok_or_else(|| value_error("nonce is required when encrypt_key is provided"))?;
            validate_len("nonce", resolved_nonce, AESGCM_NONCE_BYTES)?;
            let mut stream = Aes256GcmStreamEncryptor::new(key, resolved_nonce);
            stream.init_adata(aad);
            key.zeroize();
            encryptor = Some(stream);
        }

        Ok(Self {
            compressor: Compress::new(Compression::new(compression_level), true),
            encryptor,
            checksum: Sha256::new(),
            original_size: 0,
            compressed_size: 0,
            finished: false,
        })
    }

    fn update<'py>(&mut self, py: Python<'py>, chunk: &[u8]) -> PyResult<Py<PyBytes>> {
        if self.finished {
            return Err(value_error("PayloadStreamEncoder is already finalized"));
        }
        if chunk.is_empty() {
            return Ok(PyBytes::new(py, &[]).into());
        }

        self.original_size = self.original_size.saturating_add(chunk.len() as u64);
        self.checksum.update(chunk);

        let mut compressed = compress_all(&mut self.compressor, chunk, FlushCompress::None)?;
        self.compressed_size = self.compressed_size.saturating_add(compressed.len() as u64);

        let output = if let Some(encryptor) = &mut self.encryptor {
            let encrypted = encryptor.update(&compressed);
            compressed.zeroize();
            encrypted
        } else {
            compressed
        };

        Ok(PyBytes::new(py, &output).into())
    }

    fn finalize<'py>(&mut self, py: Python<'py>) -> PyResult<EncoderFinalizeResult> {
        if self.finished {
            return Err(value_error("PayloadStreamEncoder is already finalized"));
        }
        self.finished = true;

        let mut compressed = compress_all(&mut self.compressor, &[], FlushCompress::Finish)?;
        self.compressed_size = self.compressed_size.saturating_add(compressed.len() as u64);

        let (output, tag) = if let Some(encryptor) = &mut self.encryptor {
            let mut encrypted = encryptor.update(&compressed);
            compressed.zeroize();
            let (tail, tag) = encryptor.finalize();
            encrypted.extend_from_slice(&tail);
            (encrypted, Some(tag))
        } else {
            (compressed, None)
        };

        let checksum = self.checksum.clone().finalize();
        Ok((
            PyBytes::new(py, &output).into(),
            tag.map(|tag_bytes| PyBytes::new(py, &tag_bytes).into()),
            PyBytes::new(py, checksum.as_slice()).into(),
            self.original_size,
            self.compressed_size,
        ))
    }
}

#[pyclass(module = "avikal_backend._native")]
struct PayloadCipherVerifier {
    decryptor: Aes256GcmStreamDecryptor,
    tag: [u8; AESGCM_TAG_BYTES],
    finished: bool,
}

#[pymethods]
impl PayloadCipherVerifier {
    #[new]
    fn new(key: &[u8], nonce: &[u8], tag: &[u8], aad: &[u8]) -> PyResult<Self> {
        let mut copied_key = copy_key32(key, "key")?;
        validate_len("nonce", nonce, AESGCM_NONCE_BYTES)?;
        let copied_tag = copy_tag16(tag, "tag")?;

        let mut decryptor = Aes256GcmStreamDecryptor::new(copied_key, nonce);
        decryptor.init_adata(aad);
        copied_key.zeroize();

        Ok(Self {
            decryptor,
            tag: copied_tag,
            finished: false,
        })
    }

    fn update(&mut self, chunk: &[u8]) -> PyResult<()> {
        if self.finished {
            return Err(value_error("PayloadCipherVerifier is already finalized"));
        }
        let mut plaintext = self.decryptor.update(chunk);
        plaintext.zeroize();
        Ok(())
    }

    fn finalize(&mut self) -> PyResult<()> {
        if self.finished {
            return Err(value_error("PayloadCipherVerifier is already finalized"));
        }
        self.finished = true;

        let mut plaintext = self.decryptor.update(&self.tag);
        plaintext.zeroize();
        let mut tail = self
            .decryptor
            .finalize()
            .map_err(|_| value_error("Payload authentication failed. The archive may be corrupted or the key is incorrect."))?;
        tail.zeroize();
        Ok(())
    }
}

#[pyclass(module = "avikal_backend._native")]
struct PayloadStreamDecoder {
    decryptor: Option<Aes256GcmStreamDecryptor>,
    tag: Option<[u8; AESGCM_TAG_BYTES]>,
    decompressor: Decompress,
    checksum: Sha256,
    output_size: u64,
    max_output_size: u64,
    finished: bool,
}

impl PayloadStreamDecoder {
    fn absorb_output(&mut self, chunk: &[u8]) -> PyResult<()> {
        let next_size = self
            .output_size
            .checked_add(chunk.len() as u64)
            .ok_or_else(|| value_error("Payload expands beyond the allowed output size."))?;
        if next_size > self.max_output_size {
            return Err(value_error(
                "Payload expands beyond the allowed output size.",
            ));
        }
        self.checksum.update(chunk);
        self.output_size = next_size;
        Ok(())
    }
}

#[pymethods]
impl PayloadStreamDecoder {
    #[new]
    #[pyo3(signature = (decrypt_key=None, nonce=None, tag=None, aad=None, *, max_output_size=DEFAULT_NATIVE_DECOMPRESS_LIMIT))]
    fn new(
        decrypt_key: Option<&[u8]>,
        nonce: Option<&[u8]>,
        tag: Option<&[u8]>,
        aad: Option<&[u8]>,
        max_output_size: u64,
    ) -> PyResult<Self> {
        if max_output_size == 0 {
            return Err(value_error("Maximum output size must be positive"));
        }
        let aad = aad.unwrap_or(&[]);

        let (decryptor, copied_tag) = if let Some(key_bytes) = decrypt_key {
            let mut copied_key = copy_key32(key_bytes, "decrypt_key")?;
            let resolved_nonce = nonce
                .ok_or_else(|| value_error("nonce is required when decrypt_key is provided"))?;
            validate_len("nonce", resolved_nonce, AESGCM_NONCE_BYTES)?;
            let copied_tag = copy_tag16(
                tag.ok_or_else(|| value_error("tag is required when decrypt_key is provided"))?,
                "tag",
            )?;
            let mut decryptor = Aes256GcmStreamDecryptor::new(copied_key, resolved_nonce);
            decryptor.init_adata(aad);
            copied_key.zeroize();
            (Some(decryptor), Some(copied_tag))
        } else {
            (None, None)
        };

        Ok(Self {
            decryptor,
            tag: copied_tag,
            decompressor: Decompress::new(true),
            checksum: Sha256::new(),
            output_size: 0,
            max_output_size,
            finished: false,
        })
    }

    fn update<'py>(&mut self, py: Python<'py>, chunk: &[u8]) -> PyResult<Py<PyBytes>> {
        if self.finished {
            return Err(value_error("PayloadStreamDecoder is already finalized"));
        }

        let mut compressed = if let Some(decryptor) = &mut self.decryptor {
            decryptor.update(chunk)
        } else {
            chunk.to_vec()
        };

        let output = decompress_all(&mut self.decompressor, &compressed, FlushDecompress::None)?;
        compressed.zeroize();
        self.absorb_output(&output)?;
        Ok(PyBytes::new(py, &output).into())
    }

    fn finalize<'py>(&mut self, py: Python<'py>) -> PyResult<(Py<PyBytes>, Py<PyBytes>, u64)> {
        if self.finished {
            return Err(value_error("PayloadStreamDecoder is already finalized"));
        }
        self.finished = true;
        let mut combined_output = Vec::new();

        if let Some(decryptor) = &mut self.decryptor {
            let tag = self.tag.take().ok_or_else(|| {
                runtime_error("Encrypted payload decoder is missing its authentication tag")
            })?;
            let mut decrypted = decryptor.update(&tag);
            let mut plaintext_tail = decryptor
                .finalize()
                .map_err(|_| value_error("Payload authentication failed. The archive may be corrupted or the key is incorrect."))?;

            let inflated =
                decompress_all(&mut self.decompressor, &decrypted, FlushDecompress::None)?;
            self.absorb_output(&inflated)?;
            combined_output.extend_from_slice(&inflated);

            let final_inflated = decompress_all(
                &mut self.decompressor,
                &plaintext_tail,
                FlushDecompress::None,
            )?;
            self.absorb_output(&final_inflated)?;
            combined_output.extend_from_slice(&final_inflated);

            decrypted.zeroize();
            plaintext_tail.zeroize();
        }

        let flushed = decompress_all(&mut self.decompressor, &[], FlushDecompress::Finish)?;
        self.absorb_output(&flushed)?;
        combined_output.extend_from_slice(&flushed);

        let checksum = self.checksum.clone().finalize();
        Ok((
            PyBytes::new(py, &combined_output).into(),
            PyBytes::new(py, checksum.as_slice()).into(),
            self.output_size,
        ))
    }
}

#[pyfunction]
fn random_bytes(py: Python<'_>, length: usize) -> PyResult<Py<PyBytes>> {
    if length == 0 {
        return Err(value_error(
            "Requested random byte length must be greater than zero",
        ));
    }
    let mut output = vec![0u8; length];
    OsRng.fill_bytes(&mut output);
    Ok(PyBytes::new(py, &output).into())
}

#[pyfunction]
#[pyo3(signature = (secret, salt, *, length=32, iterations=3, lanes=4, memory_cost_kib=262144))]
fn derive_argon2id_key(
    py: Python<'_>,
    secret: &[u8],
    salt: &[u8],
    length: usize,
    iterations: u32,
    lanes: u32,
    memory_cost_kib: u32,
) -> PyResult<Py<PyBytes>> {
    validate_required_bytes("secret", secret)?;
    validate_required_bytes("salt", salt)?;
    if length == 0 {
        return Err(value_error(
            "Requested Argon2id output length must be greater than zero",
        ));
    }

    let params = Params::new(memory_cost_kib, iterations, lanes, Some(length))
        .map_err(|exc| value_error(format!("Invalid Argon2id parameters: {exc}")))?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let secret = Zeroizing::new(secret.to_vec());
    let mut output = Zeroizing::new(vec![0u8; length]);
    argon2
        .hash_password_into(&secret, salt, &mut output)
        .map_err(|exc| runtime_error(format!("Argon2id derivation failed: {exc}")))?;
    Ok(PyBytes::new(py, &output).into())
}

#[pyfunction]
#[pyo3(signature = (ikm, salt, info, *, length=32))]
fn hkdf_sha256(
    py: Python<'_>,
    ikm: &[u8],
    salt: &[u8],
    info: &[u8],
    length: usize,
) -> PyResult<Py<PyBytes>> {
    let output = hkdf_sha256_impl(ikm, salt, info, length)?;
    Ok(PyBytes::new(py, &output).into())
}

#[pyfunction]
#[pyo3(signature = (ikm, salt, info, *, length=32))]
fn hkdf_sha3_256(
    py: Python<'_>,
    ikm: &[u8],
    salt: Option<&[u8]>,
    info: &[u8],
    length: usize,
) -> PyResult<Py<PyBytes>> {
    let output = hkdf_sha3_256_impl(ikm, salt, info, length)?;
    Ok(PyBytes::new(py, &output).into())
}

#[pyfunction]
fn aes256gcm_encrypt(
    py: Python<'_>,
    key: &[u8],
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> PyResult<Py<PyBytes>> {
    let ciphertext = aes256gcm_encrypt_impl(key, nonce, plaintext, aad)?;
    Ok(PyBytes::new(py, &ciphertext).into())
}

#[pyfunction]
fn aes256gcm_decrypt(
    py: Python<'_>,
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> PyResult<Py<PyBytes>> {
    let plaintext = aes256gcm_decrypt_impl(key, nonce, ciphertext, aad)?;
    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
#[pyo3(signature = (key, base_nonce, archive_aad, payload_header, chunk_index, plaintext, compress_payload))]
fn avp_encode_chunk(
    py: Python<'_>,
    key: Option<&[u8]>,
    base_nonce: &[u8],
    archive_aad: &[u8],
    payload_header: &[u8],
    chunk_index: u64,
    plaintext: &[u8],
    compress_payload: bool,
) -> PyResult<(Py<PyBytes>, u64)> {
    if plaintext.is_empty() {
        return Err(value_error("AVP plaintext chunk must not be empty"));
    }
    if plaintext.len() > AVP_MAX_CHUNK_BYTES {
        return Err(value_error("AVP chunk size is out of bounds"));
    }
    let mut stored = if compress_payload {
        compress_chunk(plaintext)?
    } else {
        plaintext.to_vec()
    };
    let stored_len = stored.len() as u64;
    let data_len = stored.len() + if key.is_some() { AESGCM_TAG_BYTES } else { 0 };
    let chunk_header = avp_chunk_header(chunk_index, plaintext.len(), data_len)?;
    let output_data = if let Some(key_bytes) = key {
        validate_len("key", key_bytes, AES256_KEY_BYTES)?;
        let nonce = avp_chunk_nonce(base_nonce, chunk_index)?;
        let aad = avp_chunk_aad(archive_aad, payload_header, &chunk_header);
        let encrypted = aes256gcm_encrypt_impl(key_bytes, &nonce, &stored, &aad)?;
        stored.zeroize();
        encrypted
    } else {
        stored
    };
    let mut encoded = Vec::with_capacity(chunk_header.len() + output_data.len());
    encoded.extend_from_slice(&chunk_header);
    encoded.extend_from_slice(&output_data);
    Ok((PyBytes::new(py, &encoded).into(), stored_len))
}

#[pyfunction]
#[pyo3(signature = (key, base_nonce, archive_aad, payload_header, chunk_header, data, compressed))]
fn avp_decode_chunk(
    py: Python<'_>,
    key: Option<&[u8]>,
    base_nonce: &[u8],
    archive_aad: &[u8],
    payload_header: &[u8],
    chunk_header: &[u8],
    data: &[u8],
    compressed: bool,
) -> PyResult<Py<PyBytes>> {
    validate_len("chunk_header", chunk_header, AVP_CHUNK_HEADER_BYTES)?;
    let mut index_bytes = [0u8; 8];
    index_bytes.copy_from_slice(&chunk_header[..8]);
    let chunk_index = u64::from_be_bytes(index_bytes);
    let mut original_len_bytes = [0u8; 4];
    original_len_bytes.copy_from_slice(&chunk_header[8..12]);
    let original_len = u32::from_be_bytes(original_len_bytes) as usize;
    let mut data_len_bytes = [0u8; 4];
    data_len_bytes.copy_from_slice(&chunk_header[12..16]);
    let data_len = u32::from_be_bytes(data_len_bytes) as usize;
    if data_len != data.len() {
        return Err(value_error("Payload chunk data is truncated"));
    }

    let mut stored = if let Some(key_bytes) = key {
        validate_len("key", key_bytes, AES256_KEY_BYTES)?;
        let nonce = avp_chunk_nonce(base_nonce, chunk_index)?;
        let aad = avp_chunk_aad(archive_aad, payload_header, chunk_header);
        aes256gcm_decrypt_impl(key_bytes, &nonce, data, &aad)?
    } else {
        data.to_vec()
    };
    let plaintext = if compressed {
        let output = decompress_chunk(&stored)?;
        stored.zeroize();
        output
    } else {
        stored
    };
    if plaintext.len() != original_len {
        return Err(value_error("Payload chunk size verification failed"));
    }
    Ok(PyBytes::new(py, &plaintext).into())
}

#[pyfunction]
fn sha256_digest(py: Python<'_>, data: &[u8]) -> PyResult<Py<PyBytes>> {
    let digest = Sha256::digest(data);
    Ok(PyBytes::new(py, digest.as_slice()).into())
}

#[pymodule]
#[pyo3(name = "_native")]
fn avikal_backend_native(_py: Python<'_>, module: &Bound<'_, PyModule>) -> PyResult<()> {
    module.add_function(wrap_pyfunction!(random_bytes, module)?)?;
    module.add_function(wrap_pyfunction!(derive_argon2id_key, module)?)?;
    module.add_function(wrap_pyfunction!(hkdf_sha256, module)?)?;
    module.add_function(wrap_pyfunction!(hkdf_sha3_256, module)?)?;
    module.add_function(wrap_pyfunction!(aes256gcm_encrypt, module)?)?;
    module.add_function(wrap_pyfunction!(aes256gcm_decrypt, module)?)?;
    module.add_function(wrap_pyfunction!(avp_encode_chunk, module)?)?;
    module.add_function(wrap_pyfunction!(avp_decode_chunk, module)?)?;
    module.add_function(wrap_pyfunction!(sha256_digest, module)?)?;
    module.add_function(wrap_pyfunction!(
        chess_codec::encode_chess_pgn_integer,
        module
    )?)?;
    module.add_function(wrap_pyfunction!(
        chess_codec::decode_chess_pgn_integer,
        module
    )?)?;
    module.add_class::<PayloadStreamEncoder>()?;
    module.add_class::<PayloadCipherVerifier>()?;
    module.add_class::<PayloadStreamDecoder>()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pyo3::Python;

    #[test]
    fn hkdf_sha256_impl_is_deterministic() {
        let first = hkdf_sha256_impl(b"ikm", b"salt", b"context", 32).unwrap();
        let second = hkdf_sha256_impl(b"ikm", b"salt", b"context", 32).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn aes256gcm_impl_roundtrip_succeeds() {
        let key = [0x11u8; AES256_KEY_BYTES];
        let nonce = [0x22u8; AESGCM_NONCE_BYTES];
        let plaintext = b"avikal-native-roundtrip";
        let aad = b"payload-header";

        let ciphertext = aes256gcm_encrypt_impl(&key, &nonce, plaintext, aad).unwrap();
        let decrypted = aes256gcm_decrypt_impl(&key, &nonce, &ciphertext, aad).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn payload_stream_roundtrip_succeeds() {
        Python::initialize();
        let key = [0x41u8; AES256_KEY_BYTES];
        let nonce = [0x24u8; AESGCM_NONCE_BYTES];
        let aad = b"avikal-payload-aad";
        let plaintext = b"payload data ".repeat(2048);

        Python::attach(|py| {
            let mut encoder =
                PayloadStreamEncoder::new(Some(&key), Some(&nonce), Some(aad), 6).unwrap();
            let mut ciphertext = Vec::new();
            let first = PayloadStreamEncoder::update(&mut encoder, py, &plaintext[..4096]).unwrap();
            ciphertext.extend_from_slice(first.bind(py).as_bytes());
            let second =
                PayloadStreamEncoder::update(&mut encoder, py, &plaintext[4096..]).unwrap();
            ciphertext.extend_from_slice(second.bind(py).as_bytes());

            let (tail_obj, tag_obj, checksum_obj, original_size, _) =
                PayloadStreamEncoder::finalize(&mut encoder, py).unwrap();
            ciphertext.extend_from_slice(tail_obj.bind(py).as_bytes());

            let tag = tag_obj.unwrap().bind(py).as_bytes().to_vec();
            let checksum = checksum_obj.bind(py).as_bytes().to_vec();
            assert_eq!(original_size as usize, plaintext.len());

            let mut verifier = PayloadCipherVerifier::new(&key, &nonce, &tag, aad).unwrap();
            verifier
                .update(&ciphertext[..ciphertext.len() / 2])
                .unwrap();
            verifier
                .update(&ciphertext[ciphertext.len() / 2..])
                .unwrap();
            verifier.finalize().unwrap();

            let mut decoder = PayloadStreamDecoder::new(
                Some(&key),
                Some(&nonce),
                Some(&tag),
                Some(aad),
                DEFAULT_NATIVE_DECOMPRESS_LIMIT,
            )
            .unwrap();
            let first =
                PayloadStreamDecoder::update(&mut decoder, py, &ciphertext[..ciphertext.len() / 2])
                    .unwrap()
                    .bind(py)
                    .as_bytes()
                    .to_vec();
            let second =
                PayloadStreamDecoder::update(&mut decoder, py, &ciphertext[ciphertext.len() / 2..])
                    .unwrap()
                    .bind(py)
                    .as_bytes()
                    .to_vec();
            let (tail_obj, checksum_obj, output_size) =
                PayloadStreamDecoder::finalize(&mut decoder, py).unwrap();

            let mut recovered = Vec::new();
            recovered.extend_from_slice(&first);
            recovered.extend_from_slice(&second);
            recovered.extend_from_slice(tail_obj.bind(py).as_bytes());

            assert_eq!(recovered, plaintext);
            assert_eq!(checksum_obj.bind(py).as_bytes(), checksum.as_slice());
            assert_eq!(output_size as usize, plaintext.len());
        });
    }
}

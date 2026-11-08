//! Independent CM channels; legacy envelope derived from our handshake lab.
//! Modern HMAC-IV/OAEP contract: pinned SteamKit references (see notices).
use crate::bad;
use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes256,
};
use hmac::{Hmac, Mac};
use rand::{rngs::OsRng, RngCore};
use rsa::{pkcs8::DecodePublicKey, Oaep, RsaPublicKey};
use sha1::Sha1;
use std::{
    io::{self, Read, Write},
    net::{SocketAddr, TcpStream},
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use zeroize::Zeroize;
const MAX_FRAME: usize = crate::protocol::MAX_MESSAGE + 32;
#[derive(Clone)]
pub struct Envelope {
    key: [u8; 32],
    hmac: bool,
}
impl Drop for Envelope {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}
impl Envelope {
    pub fn legacy() -> Self {
        Self {
            key: [0; 32],
            hmac: false,
        }
    }
    pub fn modern(key: [u8; 32]) -> Self {
        Self { key, hmac: true }
    }
    fn digest(&self, random: &[u8], plain: &[u8]) -> [u8; 20] {
        let mut h = <Hmac<Sha1> as Mac>::new_from_slice(&self.key[..16]).unwrap();
        h.update(random);
        h.update(plain);
        h.finalize().into_bytes().into()
    }
    pub fn encode(&self, plain: &[u8]) -> Vec<u8> {
        let mut iv = [0; 16];
        OsRng.fill_bytes(&mut iv);
        if self.hmac {
            let digest = self.digest(&iv[13..], plain);
            iv[..13].copy_from_slice(&digest[..13]);
        }
        encrypt(&self.key, &iv, plain)
    }
    pub fn decode(&self, packet: &[u8]) -> io::Result<Vec<u8>> {
        let mut plain = decrypt(&self.key, packet)?;
        if self.hmac {
            let mut iv = [0; 16];
            iv.copy_from_slice(&packet[..16]);
            cipher(&self.key).decrypt_block(GenericArray::from_mut_slice(&mut iv));
            if !bool::from(self.digest(&iv[13..], &plain)[..13].ct_eq(&iv[..13])) {
                plain.zeroize();
                return Err(bad("upstream_hmac_mismatch"));
            }
        }
        Ok(plain)
    }
}
pub fn connect(address: SocketAddr, deadline: Instant) -> io::Result<(TcpStream, Envelope)> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .ok_or_else(|| bad("connect_deadline"))?;
    let mut s = TcpStream::connect_timeout(&address, remaining.min(Duration::from_secs(8)))?;
    s.set_nodelay(true)?;
    let request = read_frame(&mut s, deadline)?;
    if request.len() < 44
        || request.len() > 64
        || crate::protocol::id(&request)? != 1303
        || request[3] & 128 != 0
        || request[20..24] != [1, 0, 0, 0]
        || request[24..28] != [1, 0, 0, 0]
    {
        return Err(bad("upstream_unexpected_handshake"));
    }
    let rsa = RsaPublicKey::from_public_key_der(include_bytes!("steam-public.der"))
        .map_err(|_| bad("public_key_der"))?;
    let mut key = [0; 32];
    OsRng.fill_bytes(&mut key);
    let mut secret = key.to_vec();
    secret.extend(&request[28..]);
    let wrapped = rsa
        .encrypt(&mut OsRng, Oaep::new::<Sha1>(), &secret)
        .map_err(|_| bad("rsa_oaep"));
    secret.zeroize();
    let wrapped = wrapped?;
    let mut body = Vec::new();
    body.extend(1u32.to_le_bytes());
    body.extend((wrapped.len() as u32).to_le_bytes());
    body.extend(&wrapped);
    body.extend(crc32fast::hash(&wrapped).to_le_bytes());
    body.extend(0u32.to_le_bytes());
    send_frame(&mut s, &crate::protocol::old_message(1304, &body), deadline)?;
    let result = read_frame(&mut s, deadline)?;
    if result.len() != 24 || crate::protocol::id(&result)? != 1305 || result[20..24] != [1, 0, 0, 0]
    {
        key.zeroize();
        return Err(bad("upstream_channel_rejected"));
    }
    let envelope = Envelope::modern(key);
    key.zeroize();
    Ok((s, envelope))
}
fn cipher(key: &[u8; 32]) -> Aes256 {
    Aes256::new(GenericArray::from_slice(key))
}
fn encrypt(key: &[u8; 32], iv: &[u8; 16], plain: &[u8]) -> Vec<u8> {
    let aes = cipher(key);
    let mut out = iv.to_vec();
    aes.encrypt_block(GenericArray::from_mut_slice(&mut out));
    let mut body = plain.to_vec();
    let n = 16 - body.len() % 16;
    body.resize(body.len() + n, n as u8);
    let mut previous = *iv;
    for block in body.as_chunks_mut::<16>().0 {
        for i in 0..16 {
            block[i] ^= previous[i];
        }
        aes.encrypt_block(GenericArray::from_mut_slice(block));
        previous.copy_from_slice(block);
    }
    out.extend(body);
    out
}
fn decrypt(key: &[u8; 32], packet: &[u8]) -> io::Result<Vec<u8>> {
    if packet.len() < 32 || !packet.len().is_multiple_of(16) {
        return Err(bad("ciphertext_size"));
    }
    let aes = cipher(key);
    let mut iv = [0; 16];
    iv.copy_from_slice(&packet[..16]);
    aes.decrypt_block(GenericArray::from_mut_slice(&mut iv));
    let mut out = packet[16..].to_vec();
    for block in out.as_chunks_mut::<16>().0 {
        let mut saved = [0; 16];
        saved.copy_from_slice(block);
        aes.decrypt_block(GenericArray::from_mut_slice(block));
        for i in 0..16 {
            block[i] ^= iv[i];
        }
        iv = saved;
    }
    let pad = *out.last().unwrap() as usize;
    // Stricter than the old client's receiver: our evidence requires valid sender padding.
    if pad == 0 || pad > 16 || !out[out.len() - pad..].iter().all(|b| *b == pad as u8) {
        return Err(bad("pkcs7_invalid"));
    }
    out.truncate(out.len() - pad);
    Ok(out)
}
fn exact_until(s: &mut TcpStream, b: &mut [u8], deadline: Instant) -> io::Result<()> {
    let mut p = 0;
    while p < b.len() {
        let left = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "frame_deadline"))?;
        s.set_read_timeout(Some(left.min(Duration::from_millis(250))))?;
        match s.read(&mut b[p..]) {
            Ok(0) => return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "peer_closed")),
            Ok(n) => p += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}
pub fn read_frame(s: &mut TcpStream, deadline: Instant) -> io::Result<Vec<u8>> {
    let mut h = [0; 8];
    exact_until(s, &mut h, deadline)?;
    if &h[4..] != b"VT01" {
        return Err(bad("frame_magic"));
    }
    let n = u32::from_le_bytes(h[..4].try_into().unwrap()) as usize;
    if n == 0 || n > MAX_FRAME {
        return Err(bad("frame_length"));
    }
    let mut body = vec![0; n];
    exact_until(s, &mut body, deadline)?;
    Ok(body)
}
pub fn send_frame(s: &mut TcpStream, b: &[u8], deadline: Instant) -> io::Result<()> {
    if b.is_empty() || b.len() > MAX_FRAME {
        return Err(bad("send_frame_length"));
    }
    let mut frame = Vec::with_capacity(b.len() + 8);
    frame.extend((b.len() as u32).to_le_bytes());
    frame.extend(b"VT01");
    frame.extend(b);
    let mut p = 0;
    while p < frame.len() {
        let left = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "write_deadline"))?;
        s.set_write_timeout(Some(left.min(Duration::from_millis(250))))?;
        match s.write(&frame[p..]) {
            Ok(0) => return Err(bad("write_zero")),
            Ok(n) => p += n,
            Err(e)
                if matches!(
                    e.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

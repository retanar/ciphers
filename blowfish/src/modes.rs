use std::io::{Read, Write, Result};

use crate::blowfish::*;
use crate::consts::{BLOCK_SIZE};

fn enc8(bytes: &[u8], keys: &Keys) -> Vec<u8> {
    let (p1, p2) = encode_block(bytes_to_u32(&bytes[..4]), bytes_to_u32(&bytes[4..]), &keys);
    let mut v = Vec::with_capacity(BLOCK_SIZE);
    v.extend_from_slice(&p1.to_be_bytes());
    v.extend_from_slice(&p2.to_be_bytes());
    return v
}

fn dec8(bytes: &[u8], keys: &Keys) -> Vec<u8> {
    let (p1, p2) = decode_block(bytes_to_u32(&bytes[..4]), bytes_to_u32(&bytes[4..]), &keys);
    let mut v = Vec::with_capacity(BLOCK_SIZE);
    v.extend_from_slice(&p1.to_be_bytes());
    v.extend_from_slice(&p2.to_be_bytes());
    return v
}

pub fn pad_pkcs7(message: &[u8], block_size: usize) -> Vec<u8> {
    let padding = (block_size - (message.len() % block_size)) as u8;
    let mut v = message.to_vec();
    v.resize(block_size, padding);
    v
}

pub fn unpad_pkcs7(block: &[u8], block_size: usize) -> Vec<u8> {
    let padding = block[block.len()-1] as usize;
    if !(1..=block_size).contains(&padding) { return block.to_vec(); }
    if block[block_size-padding..].iter().all(|x| *x == padding as u8) {
        block[..block_size-padding].to_vec()
    } else { block.to_vec() }
}

pub fn enc_ecb<R, W>(input: &mut R, key: &[u8], out: &mut W) -> Result<()>
where 
    R: Read,
    W: Write,
{
    let keys = Keys::new(key);
    let mut buf = vec![0u8; BLOCK_SIZE];
    let mut read_len: usize;

    loop {
        read_len = input.read(&mut buf)?;
        if read_len < BLOCK_SIZE {
            buf = pad_pkcs7(&buf[..read_len], BLOCK_SIZE);
        }
        let encoded = enc8(&buf, &keys);
        out.write(&encoded)?;
        if read_len < BLOCK_SIZE { break; }
    }
    out.flush()?;
    Ok(())
}

pub fn dec_ecb<R, W>(input: &mut R, key: &[u8], out: &mut W) -> Result<()>
where
    R: Read,
    W: Write,
{
    let keys = Keys::new(key);
    let mut buf = vec![0u8; BLOCK_SIZE];
    let mut read_len = input.read(&mut buf)?;
    let mut decoded: Vec<u8>;

    while read_len == BLOCK_SIZE {
        decoded = dec8(&buf, &keys);
        read_len = input.read(&mut buf)?;
        if read_len < BLOCK_SIZE {
            decoded = unpad_pkcs7(&decoded, BLOCK_SIZE);
        }
        out.write(&decoded)?;
    }
    out.flush()?;
    Ok(())
}

fn xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    data.iter().zip(key.iter().cycle()).map(|(a, b)| a ^ b).collect()
}

pub fn enc_cbc<R, W>(input: &mut R, key: &[u8], iv: &[u8], out: &mut W) -> Result<()>
where
    R: Read,
    W: Write,
{
    let keys = Keys::new(key);
    let mut buf = vec![0u8; BLOCK_SIZE];
    let mut encoded = iv[..BLOCK_SIZE].to_vec();
    let mut read_len: usize;

    loop {
        read_len = input.read(&mut buf)?;
        if read_len < BLOCK_SIZE {
            buf = pad_pkcs7(&buf[..read_len], BLOCK_SIZE);
        }
        buf = xor(&buf, &encoded);
        encoded = enc8(&buf, &keys);
        out.write(&encoded)?;
        if read_len < BLOCK_SIZE { break; }
    }
    out.flush()?;
    Ok(())
}

pub fn dec_cbc<R, W>(input: &mut R, key: &[u8], iv: &[u8], out: &mut W) -> Result<()>
where
    R: Read,
    W: Write,
{
    let keys = Keys::new(key);
    let mut buf = vec![0u8; BLOCK_SIZE];
    let mut prev_enc = iv[..BLOCK_SIZE].to_vec();
    let mut read_len = input.read(&mut buf)?;

    while read_len == BLOCK_SIZE {
        let mut decoded = dec8(&buf, &keys);
        decoded = xor(&decoded, &prev_enc);
        prev_enc.copy_from_slice(&buf);
        read_len = input.read(&mut buf)?;
        if read_len < BLOCK_SIZE {
            decoded = unpad_pkcs7(&decoded, BLOCK_SIZE);
        }
        out.write(&decoded)?;
    }
    out.flush()?;
    Ok(())
}

pub fn enc_cfb<R, W>(input: &mut R, key: &[u8], iv: &[u8], out: &mut W) -> Result<()>
where
    R: Read,
    W: Write,
{
    let keys = Keys::new(key);
    let mut buf = vec![0u8; BLOCK_SIZE];
    let mut encoded = iv[..BLOCK_SIZE].to_vec();
    let mut read_len: usize;

    loop {
        read_len = input.read(&mut buf)?;
        encoded = enc8(&encoded, &keys);
        encoded = xor(&buf[..read_len], &encoded);
        out.write(&encoded)?;
        if read_len < BLOCK_SIZE { break; }
    }
    out.flush()?;
    Ok(())
}

pub fn dec_cfb<R, W>(input: &mut R, key: &[u8], iv: &[u8], out: &mut W) -> Result<()>
where
    R: Read,
    W: Write,
{
    let keys = Keys::new(key);
    let mut buf = vec![0u8; BLOCK_SIZE];
    let mut prev_enc = iv[..BLOCK_SIZE].to_vec();
    let mut read_len: usize;

    loop {
        read_len = input.read(&mut buf)?;
        let mut decoded = enc8(&prev_enc, &keys);
        decoded = xor(&buf[..read_len], &decoded);
        prev_enc.copy_from_slice(&buf);
        out.write(&decoded)?;
        if read_len < BLOCK_SIZE { break; }
    }
    out.flush()?;
    Ok(())
}

#[allow(non_upper_case_globals)]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecb_test() {
        let key: [u8; 8] = [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11];
        let plain: [u8; 16] = [0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];
        let crypted: [u8; 16] = [0x24, 0x66, 0xDD, 0x87, 0x8B, 0x96, 0x3C, 0x9D, 0x7D, 0x0C, 0xC6, 0x30, 0xAF, 0xDA, 0x1E, 0xC7];
        let mut actual = Vec::with_capacity(24);

        enc_ecb(&mut plain.clone().as_slice(), &key, &mut actual).unwrap();
        assert_eq!(&crypted, &actual[..16]);

        actual.clear();
        dec_ecb(&mut crypted.as_slice(), &key, &mut actual).unwrap();
        assert_eq!(&plain, &actual[..]);
    }

    #[test]
    fn cbc_test() {
        let plain = b"7654321 Now is the time for \x00\x00\x00\x00";
        let iv: [u8; 8] = [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        let key: [u8; 16] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87];
        let crypted: [u8; 32] = [0x6B, 0x77, 0xB4, 0xD6, 0x30, 0x06, 0xDE, 0xE6, 0x05, 0xB1, 0x56, 0xE2, 0x74, 0x03, 0x97, 0x93, 0x58, 0xDE, 0xB9, 0xE7, 0x15, 0x46, 0x16, 0xD9, 0x59, 0xF1, 0x65, 0x2B, 0xD5, 0xFF, 0x92, 0xCC];
        let mut actual = Vec::with_capacity(32);

        enc_cbc(&mut plain.as_slice(), &key, &iv, &mut actual).unwrap();
        assert_eq!(&crypted, &actual[..32]);

        actual.clear();
        dec_cbc(&mut crypted.as_slice(), &key, &iv, &mut actual).unwrap();
        assert_eq!(&plain, &actual.as_slice());
    }

    #[test]
    fn cfb_test() {
        let plain = b"7654321 Now is the time for \x00";
        let iv: [u8; 8] = [0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10];
        let key: [u8; 16] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87];
        let crypted: [u8; 29] = [0xE7, 0x32, 0x14, 0xA2, 0x82, 0x21, 0x39, 0xCA, 0xF2, 0x6E, 0xCF, 0x6D, 0x2E, 0xB9, 0xE7, 0x6E, 0x3D, 0xA3, 0xDE, 0x04, 0xD1, 0x51, 0x72, 0x00, 0x51, 0x9D, 0x57, 0xA6, 0xC3];
        let mut actual = Vec::with_capacity(crypted.len());

        enc_cfb(&mut plain.as_slice(), &key, &iv, &mut actual).unwrap();
        assert_eq!(&crypted, &actual[..]);

        actual.clear();
        dec_cfb(&mut crypted.as_slice(), &key, &iv, &mut actual).unwrap();
        assert_eq!(&plain, &actual.as_slice());
    }
}

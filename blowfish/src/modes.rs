use std::io::{Read, Write};

use crate::blowfish::*;

fn enc8(bytes: &[u8], keys: &Keys) -> Vec<u8> {
    let (p1, p2) = encode_block(bytes_to_u32(&bytes[..4]), bytes_to_u32(&bytes[4..]), &keys);
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(&p1.to_be_bytes());
    v.extend_from_slice(&p2.to_be_bytes());
    return v
}

fn dec8(bytes: &[u8], keys: &Keys) -> Vec<u8> {
    let (p1, p2) = decode_block(bytes_to_u32(&bytes[..4]), bytes_to_u32(&bytes[4..]), &keys);
    let mut v = Vec::with_capacity(8);
    v.extend_from_slice(&p1.to_be_bytes());
    v.extend_from_slice(&p2.to_be_bytes());
    return v
}

pub fn pad_pkcs7(message: &[u8], block_size: usize) -> Vec<u8> {
    let pad_size = (block_size - (message.len() % block_size)) as u8;
    let mut v = message.to_vec();
    v.resize(block_size, pad_size);
    v
}

pub fn unpad_pkcs7(block: &[u8], block_size: usize) -> Vec<u8> {
    let padding = block[block.len()-1] as usize;
    if !(1..=block_size).contains(&padding) { return block.to_vec(); }
    if block[block_size-padding..].iter().all(|x| *x == padding as u8) {
        block[..block_size-padding].to_vec()
    } else { block.to_vec() }
}

pub fn enc_ecb<R, W>(input: &mut R, key: &[u8], out: &mut W)
where 
    R: Read,
    W: Write,
{
    let keys = Keys::new(key);
    let mut buf = vec![0u8; 8];
    let mut read_len: usize;

    loop {
        read_len = input.read(&mut buf).unwrap();
        if read_len < 8 { break; }
        let encoded = enc8(&buf, &keys);
        out.write(&encoded);
    }
    let last = enc8(&pad_pkcs7(&buf[..read_len], 8), &keys);
    out.write(&last);
    out.flush();
}

pub fn dec_ecb<R, W>(input: &mut R, key: &[u8], out: &mut W)
where
    R: Read,
    W: Write,
{
    let keys = Keys::new(key);
    let mut buf = vec![0u8; 8];
    let mut read_len = input.read(&mut buf).unwrap();
    let mut decoded: Vec<u8>;

    loop {
        decoded = dec8(&buf, &keys);
        read_len = input.read(&mut buf).unwrap();
        if read_len == 0 { break; }
        out.write(&decoded);
    }
    let last = unpad_pkcs7(&decoded, 8);
    out.write(&last);
    out.flush();
}


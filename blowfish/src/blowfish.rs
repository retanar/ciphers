use std::mem;
use std::borrow::Borrow;

use crate::consts;

fn encode_block(xl: u32, xr: u32, keys: &Keys) -> (u32, u32) {
    let mut xl = xl;
    let mut xr = xr;
    for i in 0usize..16usize {
        xl = xl ^ keys.parray[i];
        xr = f(xl, &keys) ^ xr;
        mem::swap(&mut xl, &mut xr);
    }
    mem::swap(&mut xl, &mut xr);
    xr ^= keys.parray[16];
    xl ^= keys.parray[17];
    return (xl, xr);
}

fn f(int: u32, keys: &Keys) -> u32 {
    let bytes = int.to_be_bytes();
    let part = keys.sbox[0][bytes[0] as usize].wrapping_add(keys.sbox[1][bytes[1] as usize]);
    return (part ^ keys.sbox[2][bytes[2] as usize]).wrapping_add(keys.sbox[3][bytes[3] as usize]);
}

fn decode_block(xl: u32, xr: u32, keys: &Keys) -> (u32, u32) {
    let mut xl = xl;
    let mut xr = xr;
    for i in (2..18usize).rev() {
        xl = xl ^ keys.parray[i];
        xr = f(xl, &keys) ^ xr;
        mem::swap(&mut xl, &mut xr);
    }
    mem::swap(&mut xl, &mut xr);
    xr ^= keys.parray[1];
    xl ^= keys.parray[0];
    return (xl, xr);
}

fn bytes_to_u32<I>(arr: I) -> u32
where
    I: IntoIterator,
    I::Item: Borrow<u8>,
{
    arr.into_iter().take(4).fold(0u32, |acc, x| (acc << 8) | *x.borrow() as u32)
}

struct Keys {
    pub parray: [u32; 18],
    pub sbox: [[u32; 256]; 4],
}

impl Keys {
    pub fn new(key: &[u8]) -> Self {
        let mut keys = Keys { parray: consts::PARRAY, sbox: consts::SBOX };
        let mut key_iter = key.iter().cycle();
    
        for i in 0..18 {
            let key32 = bytes_to_u32(&mut key_iter);
            keys.parray[i] ^= key32;
        }
        
        let mut l = 0;
        let mut r = 0;
        for i in (0..18).step_by(2) {
            (l, r) = encode_block(l, r, &keys);
            keys.parray[i] = l;
            keys.parray[i+1] = r;
        }
        for i in 0..4 {
            for j in (0..keys.sbox[i].len()).step_by(2) {
                (l, r) = encode_block(l, r, &keys);
                keys.sbox[i][j] = l;
                keys.sbox[i][j+1] = r;
            }
        }
    
        return keys;
    }
}

#[allow(non_upper_case_globals)]
#[cfg(test)]
mod tests {
    use super::*;

    const VAR_KEY_TESTS: usize = 34;

    const plain_l: [u32; VAR_KEY_TESTS] = [
        0x00000000, 0xFFFFFFFF, 0x10000000, 0x11111111, 0x11111111,
        0x01234567, 0x00000000, 0x01234567, 0x01A1D6D0, 0x5CD54CA8,
        0x0248D438, 0x51454B58, 0x42FD4430, 0x059B5E08, 0x0756D8E0,
        0x762514B8, 0x3BDD1190, 0x26955F68, 0x164D5E40, 0x6B056E18,
        0x004BD6EF, 0x480D3900, 0x437540C8, 0x072D43A0, 0x02FE5577,
        0x1D9D5C50, 0x30553228, 0x01234567, 0x01234567, 0x01234567,
        0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF];
    const plain_r: [u32; VAR_KEY_TESTS] = [
        0x00000000, 0xFFFFFFFF, 0x00000001, 0x11111111, 0x11111111,
        0x89ABCDEF, 0x00000000, 0x89ABCDEF, 0x39776742, 0x3DEF57DA,
        0x06F67172, 0x2DDF440A, 0x59577FA2, 0x51CF143A, 0x774761D2,
        0x29BF486A, 0x49372802, 0x35AF609A, 0x4F275232, 0x759F5CCA,
        0x09176062, 0x6EE762F2, 0x698F3CFA, 0x77075292, 0x8117F12A,
        0x18F728C2, 0x6D6F295A, 0x89ABCDEF, 0x89ABCDEF, 0x89ABCDEF,
        0xFFFFFFFF, 0x00000000, 0x00000000, 0xFFFFFFFF];
    const var_key: [[u8; 8]; VAR_KEY_TESTS] = [
        [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
        [ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ],
        [ 0x30, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
        [ 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 ],
        [ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF ],
        [ 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11 ],
        [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
        [ 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 ],
        [ 0x7C, 0xA1, 0x10, 0x45, 0x4A, 0x1A, 0x6E, 0x57 ],
        [ 0x01, 0x31, 0xD9, 0x61, 0x9D, 0xC1, 0x37, 0x6E ],
        [ 0x07, 0xA1, 0x13, 0x3E, 0x4A, 0x0B, 0x26, 0x86 ],
        [ 0x38, 0x49, 0x67, 0x4C, 0x26, 0x02, 0x31, 0x9E ],
        [ 0x04, 0xB9, 0x15, 0xBA, 0x43, 0xFE, 0xB5, 0xB6 ],
        [ 0x01, 0x13, 0xB9, 0x70, 0xFD, 0x34, 0xF2, 0xCE ],
        [ 0x01, 0x70, 0xF1, 0x75, 0x46, 0x8F, 0xB5, 0xE6 ],
        [ 0x43, 0x29, 0x7F, 0xAD, 0x38, 0xE3, 0x73, 0xFE ],
        [ 0x07, 0xA7, 0x13, 0x70, 0x45, 0xDA, 0x2A, 0x16 ],
        [ 0x04, 0x68, 0x91, 0x04, 0xC2, 0xFD, 0x3B, 0x2F ],
        [ 0x37, 0xD0, 0x6B, 0xB5, 0x16, 0xCB, 0x75, 0x46 ],
        [ 0x1F, 0x08, 0x26, 0x0D, 0x1A, 0xC2, 0x46, 0x5E ],
        [ 0x58, 0x40, 0x23, 0x64, 0x1A, 0xBA, 0x61, 0x76 ],
        [ 0x02, 0x58, 0x16, 0x16, 0x46, 0x29, 0xB0, 0x07 ],
        [ 0x49, 0x79, 0x3E, 0xBC, 0x79, 0xB3, 0x25, 0x8F ],
        [ 0x4F, 0xB0, 0x5E, 0x15, 0x15, 0xAB, 0x73, 0xA7 ],
        [ 0x49, 0xE9, 0x5D, 0x6D, 0x4C, 0xA2, 0x29, 0xBF ],
        [ 0x01, 0x83, 0x10, 0xDC, 0x40, 0x9B, 0x26, 0xD6 ],
        [ 0x1C, 0x58, 0x7F, 0x1C, 0x13, 0x92, 0x4F, 0xEF ],
        [ 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01, 0x01 ],
        [ 0x1F, 0x1F, 0x1F, 0x1F, 0x0E, 0x0E, 0x0E, 0x0E ],
        [ 0xE0, 0xFE, 0xE0, 0xFE, 0xF1, 0xFE, 0xF1, 0xFE ],
        [ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 ],
        [ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF ],
        [ 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF ],
        [ 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10 ]];
    const cipher_l: [u32; VAR_KEY_TESTS] = [
        0x4EF99745, 0x51866FD5, 0x7D856F9A, 0x2466DD87, 0x61F9C380,
        0x7D0CC630, 0x4EF99745, 0x0ACEAB0F, 0x59C68245, 0xB1B8CC0B,
        0x1730E577, 0xA25E7856, 0x353882B1, 0x48F4D088, 0x432193B7,
        0x13F04154, 0x2EEDDA93, 0xD887E039, 0x5F99D04F, 0x4A057A3B,
        0x452031C1, 0x7555AE39, 0x53C55F9C, 0x7A8E7BFA, 0xCF9C5D7A,
        0xD1ABB290, 0x55CB3774, 0xFA34EC48, 0xA7907951, 0xC39E072D,
        0x014933E0, 0xF21E9A77, 0x24594688, 0x6B5C5A9C];
    const cipher_r: [u32; VAR_KEY_TESTS] = [
        0x6198DD78, 0xB85ECB8A, 0x613063F2, 0x8B963C9D, 0x2281B096,
        0xAFDA1EC7, 0x6198DD78, 0xC6A0A28D, 0xEB05282B, 0x250F09A0,
        0x8BEA1DA4, 0xCF2651EB, 0x09CE8F1A, 0x4C379918, 0x8951FC98,
        0xD69D1AE5, 0xFFD39C79, 0x3C2DA6E3, 0x5B163969, 0x24D3977B,
        0xE4FADA8E, 0xF59B87BD, 0xB49FC019, 0x937E89A3, 0x4986ADB5,
        0x658BC778, 0xD13EF201, 0x47B268B2, 0x08EA3CAE, 0x9FAC631D,
        0xCDAFF6E4, 0xB71C49BC, 0x5754369A, 0x5D9E0A5A];

    #[test]
    fn var_key_tests() {
        for i in 0..VAR_KEY_TESTS {
            let keys = Keys::new(&var_key[i]);
            assert_eq!((cipher_l[i], cipher_r[i]), encode_block(plain_l[i], plain_r[i], &keys));
            assert_eq!((plain_l[i], plain_r[i]), decode_block(cipher_l[i], cipher_r[i], &keys));
        }
    }

    const SET_KEY_TESTS: usize = 24;
    const set_plain_l: u32 = 0xFEDCBA98;
    const set_plain_r: u32 = 0x76543210;
    const set_cipher_l: [u32; SET_KEY_TESTS] = [
        0xF9AD597C, 0xE91D21C1, 0xE9C2B70A, 0xBE1E6394, 0xB39E4448, 
        0x9457AA83, 0x8BB77032, 0xE87A244E, 0x15750E7A, 0x122BA70B, 
        0x3A833C9A, 0x9409DA87, 0x884F8062, 0x1F85031C, 0x79D9373A, 
        0x93142887, 0x03429E83, 0xA4299E27, 0xAFD5AED1, 0x10851C0E, 
        0xE6F51ED7, 0x64A6E14A, 0x80C7D7D4, 0x05044B62];    
    const set_cipher_r: [u32; SET_KEY_TESTS] = [        
        0x49DB005E, 0xD961A6D6, 0x1BC65CF3, 0x08640F05, 0x1BDB1E6E, 
        0xB1928C0D, 0xF960629D, 0x2CC85E82, 0x4F4EC577, 0x3AB64AE0, 
        0xFFC537F6, 0xA90F6BF2, 0x5060B8B4, 0x19E11968, 0x714CA34F, 
        0xEE3BE15C, 0x8CE2D14B, 0x469FF67B, 0xC1BC96A8, 0x3858DA9F, 
        0x9B9DB21F, 0xFD36B46F, 0x5A5479AD, 0xFA52D080];    
    const set_key: [u8; SET_KEY_TESTS] = [
        0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87,
        0x78, 0x69, 0x5A, 0x4B, 0x3C, 0x2D, 0x1E, 0x0F,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77];

    #[test]
    fn set_key_tests() {
        for i in 0..SET_KEY_TESTS {
            let keys = Keys::new(&set_key[..i+1]);
            assert_eq!((set_cipher_l[i], set_cipher_r[i]), encode_block(set_plain_l, set_plain_r, &keys));
            assert_eq!((set_plain_l, set_plain_r), decode_block(set_cipher_l[i], set_cipher_r[i], &keys));
        }
    }

    #[test]
    fn bytes_to_u32_test() {
        let mut cycle = [1, 2, 3u8].as_slice().iter().cycle();
        assert_eq!(bytes_to_u32(&mut cycle), 0x01020301u32);
        assert_eq!(bytes_to_u32(&mut cycle), 0x02030102u32);

        let slice = [1, 2, 3, 4u8].as_slice();
        assert_eq!(bytes_to_u32(slice), 0x01020304u32);
        assert_eq!(bytes_to_u32(slice), 0x01020304u32);
    }
}


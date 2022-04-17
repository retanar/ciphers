use std::io::{BufReader, BufWriter, Read, Write};
use std::fs::File;
use std::env;

struct LFSR {
    reg: u64,
    taps: Vec<u8>,
    bit_len: u8,
}

impl LFSR {
    fn new(taps: &[u8], init: u64, length: u8) -> Self {
        if init == 0 { panic!("Init value shouldn't be 0"); }
        if length <= 0 || length > 64 { panic!("Register length should be in (0;64]"); }
        if taps.len() <= 1 { panic!("Should provide at least two taps"); }
        LFSR {
            reg: init,
            taps: taps.to_vec(),
            bit_len: length,
        }
    }

    fn xor(&self) -> u64 {
        self.taps.iter()
            .map(|i| (self.reg >> i) & 1)
            .reduce(core::ops::BitXor::bitxor).unwrap()
    }

    /// Returns next bit in the register and shifts the register
    fn gen_bit(&mut self) -> u64 {
        let new_bit = self.reg & 1;
        self.shift();
        new_bit
    }

    fn shift(&mut self) {
        let bit = self.xor();
        self.reg >>= 1;
        self.reg |= bit << (self.bit_len - 1u8);
    }

    fn gen_byte(&mut self) -> u8 {
        // let out = self.reg as u8;
        // for _ in 0..8 { self.shift(); }
        // out
        (0..8).fold(0u8, |acc, _| (acc << 1) | self.gen_bit() as u8)
    }
}

fn xor_file(rpath: &str, wpath: &str, lfsr: &mut LFSR) -> std::io::Result<()> {
    let reader = BufReader::new(File::open(rpath)?).bytes();
    let mut writer = BufWriter::new(File::create(wpath)?);
    for byte in reader {
        writer.write(&[byte.unwrap() ^ lfsr.gen_byte()])?;
    }
    writer.flush()?;
    Ok(())
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let fin = &args[1];
    let fout = &args[2];

    let mut taps_str = String::new();
    let mut init_str = String::new();
    
    print!("Enter comma separated taps: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut taps_str).unwrap();
    let taps = taps_str.split(',')
        .map(|s| s.trim().parse().expect("Number is too big or incorrect"))
        .collect::<Vec<u8>>();

    print!("Enter 64 bit initialisation value in hex: ");
    std::io::stdout().flush().unwrap();
    std::io::stdin().read_line(&mut init_str).unwrap();
    let init = u64::from_str_radix(init_str.trim(), 16).expect("Number is too big or incorrect");
    //let init = 0xABCDABCD_ABCDABCDu64;

    let mut reg = LFSR::new(taps.as_slice(), init as u64, 64);
    xor_file(fin, fout, &mut reg).unwrap();
}

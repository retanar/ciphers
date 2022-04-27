use std::io::{BufReader, BufWriter, Write};
use std::fs::File;
use std::env;

pub mod blowfish;
pub mod consts;
pub mod modes;

const VALID_MODES: [&str; 3] = ["ecb", "cbc", "cfb"];

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 || ["-h", "--help"].contains(&args[1].as_str()) {
        println!("HELP");
        return;
    }

    let in_path = &args[2];
    let out_path = &args[3];

    let encryption = match args[1].as_str() {
        "-d" | "--decrypt" => false,
        "-e" | "--encrypt" => true,
        _ => panic!("Incorrect option"),
    };

    let mut in_file = BufReader::new(File::open(in_path).expect("Wrong input path."));
    let mut out_file = BufWriter::new(File::create(out_path).expect("Wrong output path."));
    
    let mut mode = String::new();
    let mut hex_password = String::new();
    let mut hex_iv = String::new();
    let password: Vec<u8>;
    let mut iv = Vec::new();

    while !VALID_MODES.contains(&mode.as_str()) {
        mode.clear();
        print!("Enter mode({}): ", VALID_MODES.join(","));
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_line(&mut mode).unwrap();
        mode = mode.trim().to_ascii_lowercase();
    }

    if !mode.eq_ignore_ascii_case("ecb") {
        loop {
            hex_iv.clear();
            print!("Enter iv (8 bytes, hex): ");
            std::io::stdout().flush().unwrap();
            std::io::stdin().read_line(&mut hex_iv).unwrap();
            hex_iv = hex_iv.trim().to_owned();

            if hex_iv.len() != consts::BLOCK_SIZE * 2 ||
               !hex_iv.chars().all(|c| c.is_ascii_hexdigit()) {
                println!("Incorrect iv.");
            } else { break; }
        }
        iv = hex_to_bytes(&hex_iv);
    }

    loop {
        hex_password.clear();
        print!("Enter password (1-72 bytes, hex): ");
        std::io::stdout().flush().unwrap();
        std::io::stdin().read_line(&mut hex_password).unwrap();
        hex_password = hex_password.trim().to_owned();

        if hex_password.len() < 1 || hex_password.len() > 72 ||
           !hex_password.chars().all(|c| c.is_ascii_hexdigit()) {
            println!("Incorrect password");
        } else { break; }
    }
    password = hex_to_bytes(&hex_password);

    if encryption {
        match mode.as_str() {
            "ecb" => modes::enc_ecb(&mut in_file, &password, &mut out_file).unwrap(),
            "cbc" => modes::enc_cbc(&mut in_file, &password, &iv, &mut out_file).unwrap(),
            "cfb" => modes::enc_cfb(&mut in_file, &password, &iv, &mut out_file).unwrap(),
            _ => (),
        }
    } else {
        match mode.as_str() {
            "ecb" => modes::dec_ecb(&mut in_file, &password, &mut out_file).unwrap(),
            "cbc" => modes::dec_cbc(&mut in_file, &password, &iv, &mut out_file).unwrap(),
            "cfb" => modes::dec_cfb(&mut in_file, &password, &iv, &mut out_file).unwrap(),
            _ => (),
        }
    }
    println!("Done.");
}

fn hex_to_bytes(hexstr: &str) -> Vec<u8> {
    (2..=hexstr.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hexstr[(i-2)..i], 16).unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_to_bytes_test() {
        assert_eq!(hex_to_bytes("Af901C").as_slice(), [0xaf, 0x90, 0x1c]);
        assert_eq!(hex_to_bytes("Af901Ce").as_slice(), [0xaf, 0x90, 0x1c]);
    }
}

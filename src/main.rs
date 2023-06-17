use openssl::bn::BigNum;
use openssl::rsa::{Padding, Rsa};
use openssl::pkey::{Public};
use openssl::error::ErrorStack;
use openssl::hash::{hash, MessageDigest};
use rand::prelude::*;
use std::net::{UdpSocket};
use csv;
use std::collections::HashMap;


const ANSI_GRAY: &str = "\x1b[90m";
const ANSI_RESET: &str = "\x1b[0m";


enum Protocol {
    PROTOCOL_1,
    PROTOCOL_2,
    PROTOCOL_3
}





fn read_lookup_table_from_csv(path: &str) -> HashMap<String, String> {
    let mut reader = csv::Reader::from_path(path).unwrap();
    let mut lookup_table = HashMap::new();
    for result in reader.records() {
        let record = result.unwrap();
        lookup_table.insert(record[2].to_string(), record[3].to_string());
    }
    lookup_table
}



fn hexdump(data: &[u8]) {
    // print data in the same format as `hexdump -C`,
    // with ascii characters in the left margin
    print!("{}", ANSI_GRAY);
    for (i, chunk) in data.chunks(16).enumerate() {
        print!("{:04x}  ", i * 16);
        for (j, byte) in chunk.iter().enumerate() {
            print!("{:02x} ", byte);
            if j == 7 {
                print!(" ");
            }
        }
        if chunk.len() < 16 {
            for _ in 0..(16 - chunk.len()) {
                print!("   ");
            }
        }
        print!("|");
        for byte in chunk {
            if *byte >= 0x20 && *byte <= 0x7e {
                print!("{}", *byte as char);
            } else {
                print!(".");
            }
        }
        println!("|");
    }
    print!("{}", ANSI_RESET);
}


fn md5(data: &[u8]) -> Vec<u8> {
    hash(MessageDigest::md5(), data).unwrap().to_vec()
}


fn mkrsa(e: &str, n: &str) -> Result<Rsa<Public>, ErrorStack> {
    let e = BigNum::from_hex_str(e)?;
    let n = BigNum::from_hex_str(n)?;
    return Rsa::from_public_components(n, e)
}


fn random_bytes(buf: &mut [u8]) {
    let len = buf.len();
    let mut rng = thread_rng();
    for i in 0..len {
        buf[i] = rng.gen();
    }
}


fn find_phony_ciphertext(
    rsa: &Rsa<Public>,
    predicate: &dyn Fn(&[u8]) -> bool) -> Vec<u8> {
    let mut ciphertext = vec![0; 0x80];
    let mut plaintext = vec![0; 0x80];
    let mut tries = 0;
    
    loop {
        tries += 1;
        random_bytes(&mut ciphertext);
        match rsa.public_decrypt(&ciphertext, &mut plaintext, Padding::NONE) {
            Ok(_) => {
                if predicate(&plaintext) {
                    println!("Found phony ciphertext after {} tries", tries);
                    return ciphertext;
                }
            },
            Err(_) => {}
        }
    }
}


fn communicate(addr: &str, port: u16, data: &[u8], await_reply: bool) -> std::io::Result<Vec<u8>> {
    let mut bindaddr;
    let mut socket;
    let mut p = port;
    loop {
        p += 1;
        if p > 65534 {
            panic!("No free port found");
        }
        bindaddr = format!("0.0.0.0:{}", p);
        match UdpSocket::bind(bindaddr.clone()) {
            Ok(s) => {
                println!("Bound to {}", bindaddr);
                socket = s;
                break;
            },
            Err(_) => {}
        }
    }
    println!("Sending {} bytes to {}:{}", data.len(), addr, port);

    socket.connect((addr, port))?;
    socket.send(data)?;
    let mut buf = vec![0; 0x100];
    if await_reply {
        let len = socket.recv(&mut buf)?;
        buf.truncate(len);
        return Ok(buf); 
    } else {
        return Ok(vec![]);
    }
}


fn device_identifying_hash(idstr: &str) -> Vec<u8> {
    let mut data = vec![0; 0x80];
    data[0..idstr.len()].copy_from_slice(idstr.as_bytes());
    md5(&data)
}


fn stage1(addr: &str, port: u16, lookup: HashMap<String,String>) -> std::io::Result<String> {
    let data = "ABCDEF1234".as_bytes();
    let id = communicate(addr, port, &data, true)?;

    // now iterate through the lookup table and find a match
    for (idstr, pubkey) in lookup.iter() {
        let hash = device_identifying_hash(idstr);
        if hash == id {
            println!("Found key for device: {} -> {}", idstr, pubkey);
            return Ok(pubkey.to_string());
        }
    }

    Err(std::io::Error::new(std::io::ErrorKind::Other, "No match found"))
}


fn stage2(addr: &str, port: u16, pubkey: &str, protocol: Protocol) -> std::io::Result<Vec<u8>> {
    let rsa = mkrsa("010001", pubkey)?;
    // use for protocols 2 and 3
    fn first_byte_printable(data: &[u8]) -> bool {
        return data[0] >= 0x20 && data[0] < 0x7f;
    }
    // use for protocol 1
    fn first_byte_null(data: &[u8]) -> bool {
        return data[0] == 0;
    }

    let predicate = match protocol {
        Protocol::PROTOCOL_1 => first_byte_null,
        Protocol::PROTOCOL_2 => first_byte_printable,
        Protocol::PROTOCOL_3 => first_byte_printable
    };

    let ciphertext = find_phony_ciphertext(&rsa, &predicate);
    let challenge = communicate(addr, port, &ciphertext, false);
    // ignoring challenge, we're hacking this
    Ok(challenge)
}


fn stage3(addr: &str, port: u16, salt: &str) -> std::io::Result<Vec<u8>> {
    let password = md5(format!("+{}", salt));
    println!("Password prepared:");
    hexdump(&password);
    let res = communicate(addr, port, &password, true)?;
    Ok(res)
}


fn main() {
    let e = "10001";
    let n = "E541A631680C453DF31591A6E29382BC5EAC969DCFDBBCEA64CB49CBE36578845C507BF5E7A6BCD724AFA7063CA754826E8D13DBA18A2359EB54B5BE3368158824EA316A495DDC3059C478B41ABF6B388451D38F3C6650CDB4590C1208B91F688D0393241898C1F05A6D500C7066298C6BA2EF310F6DB2E7AF52829E9F858691";
    let rsa = mkrsa(e, n).unwrap();

    fn first_byte_printable(data: &[u8]) -> bool {
        return data[0] >= 0x20 && data[0] < 0x7f;
    }

    let lookup = read_lookup_table_from_csv("data/keychain.csv");
    println!("Loaded {} entries from keychain.csv", lookup.len());
    for (key, value) in lookup.iter() {
        println!("{} -> {}", key, value);
    }

    for i in 0..10 {
        let phony = find_phony_ciphertext(&rsa, &first_byte_printable);
        hexdump(&phony);
        let mut plain = vec![0; 0x80];
        rsa.public_decrypt(&phony, &mut plain, Padding::NONE).unwrap();
        println!("Plaintext:");
        hexdump(&plain);
        let resp = communicate("127.0.0.1", 21210, &phony, true).unwrap();
        println!("Response:");
        hexdump(&resp);
    }
}

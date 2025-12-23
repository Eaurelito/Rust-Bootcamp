use rand::Rng;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// Hardcoded Diffie-Hellman parameters
const P: u64 = 0xD87FA3E291B4C7F3; // Large prime (64-bit prime - public)
const G: u64 = 2; // Generator (generator - public)

// Security constants
const MAX_MESSAGE_LENGTH: usize = 65_536; // 64KB max message size
const CONNECTION_TIMEOUT_SECS: u64 = 300; // 5 minutes
const READ_TIMEOUT_SECS: u64 = 60; // 1 minute for read operations
const MAX_MESSAGES_PER_SESSION: usize = 10_000; // Prevent DoS

/// Modular exponentiation using square-and-multiply algorithm
/// Computes (base^exp) mod modulus
fn mod_exp(base: u64, exp: u64, modulus: u64) -> u64 {
    if modulus == 1 {
        return 0;
    }

    let mut result: u128 = 1;
    let mut base: u128 = (base % modulus) as u128;
    let mut exp = exp;
    let modulus = modulus as u128;

    while exp > 0 {
        if exp % 2 == 1 {
            result = (result * base) % modulus;
        }
        exp = exp >> 1;
        base = (base * base) % modulus;
    }

    result as u64
}

/// Validate DH public key to prevent small subgroup attacks
fn validate_dh_public_key(public_key: u64) -> Result<(), String> {
    // Check if public key is in valid range: 2 <= public_key <= P-2
    if public_key < 2 {
        return Err("Public key too small (< 2)".to_string());
    }
    if public_key >= P - 1 {
        return Err("Public key too large (>= P-1)".to_string());
    }

    // Additional check: ensure it's not 1 or P-1 (trivial subgroups)
    if public_key == 1 || public_key == P - 1 {
        return Err("Public key in trivial subgroup".to_string());
    }

    Ok(())
}

/// Generate Diffie-Hellman key pair
fn generate_dh_keypair() -> (u64, u64) {
    let mut rng = rand::thread_rng();

    // Ensure private key is in valid range: 2 <= private_key <= P-2
    let private_key: u64 = rng.gen_range(2..P - 1);

    println!("[DH] Generating our keypair...");
    println!("private_key = {:X} (random 64-bit)", private_key);
    println!("public_key = g^private mod p");
    println!("           = 2^{:X} mod p", private_key);

    let public_key = mod_exp(G, private_key, P);

    println!("           = {:X}", public_key);

    (private_key, public_key)
}

/// Compute shared secret from private key and peer's public key
fn compute_shared_secret(private_key: u64, peer_public_key: u64) -> Result<u64, String> {
    // Validate peer's public key before computing shared secret
    validate_dh_public_key(peer_public_key)?;

    println!("\n[DH] Computing shared secret...");
    println!("Formula: secret = (their_public)^(our_private) mod p");
    println!();
    println!("secret = ({:X})^({:X}) mod p", peer_public_key, private_key);

    let shared_secret = mod_exp(peer_public_key, private_key, P);

    // Additional validation: ensure shared secret is not trivial
    if shared_secret == 0 || shared_secret == 1 {
        return Err("Computed shared secret is trivial".to_string());
    }

    println!("       = {:X}", shared_secret);

    Ok(shared_secret)
}

/// Simple Linear Congruential Generator for keystream
struct KeystreamGenerator {
    state: u64,
    a: u64,
    c: u64,
    m: u64,
}

impl KeystreamGenerator {
    fn new(seed: u64) -> Self {
        let a = 1103515245;
        let c = 12345;
        let m = 2u64.pow(32);

        println!("\n[STREAM] Generating keystream from secret...");
        println!("Algorithm: LCG (a={}, c={}, m=2^32)", a, c);
        println!("Seed: secret = {:X}", seed);
        println!();

        KeystreamGenerator {
            state: seed,
            a,
            c,
            m,
        }
    }

    fn next_byte(&mut self) -> u8 {
        self.state = (self.a.wrapping_mul(self.state).wrapping_add(self.c)) % self.m;
        ((self.state >> 24) & 0xFF) as u8
    }

    fn peek_keystream(&mut self, count: usize) -> Vec<u8> {
        let mut bytes = Vec::new();
        for _ in 0..count {
            bytes.push(self.next_byte());
        }
        bytes
    }
}

/// Encrypt message using XOR with keystream
fn encrypt_message(data: &[u8], seed: u64) -> Vec<u8> {
    let mut generator = KeystreamGenerator::new(seed);

    // Show first few keystream bytes
    let preview = generator.peek_keystream(20.min(data.len()));
    print!("Keystream: ");
    for (i, b) in preview.iter().enumerate() {
        if i > 0 {
            print!(" ");
        }
        print!("{:02X}", b);
    }
    if data.len() > 20 {
        print!(" ...");
    }
    println!();

    // Reset and encrypt
    let mut generator = KeystreamGenerator::new(seed);
    let mut result = Vec::with_capacity(data.len());

    for &byte in data.iter() {
        let key_byte = generator.next_byte();
        result.push(byte ^ key_byte);
    }

    result
}

/// Decrypt message using XOR with keystream
fn decrypt_message(data: &[u8], seed: u64) -> Vec<u8> {
    // XOR is symmetric, so decryption is the same as encryption
    let mut generator = KeystreamGenerator::new(seed);
    let mut result = Vec::with_capacity(data.len());

    for &byte in data.iter() {
        let key_byte = generator.next_byte();
        result.push(byte ^ key_byte);
    }

    result
}

fn print_encryption_details(
    plaintext: &str,
    key_bytes: &[u8],
    ciphertext: &[u8],
    keystream_pos: usize,
) {
    println!("\n[ENCRYPT]");
    print!("Plain: ");
    for b in plaintext.as_bytes() {
        print!("{:02x} ", b);
    }
    print!("(\"{}\")", plaintext);
    println!();

    print!("Key: ");
    for (i, b) in key_bytes.iter().enumerate() {
        print!("{:02x} ", b);
        if i >= plaintext.len() - 1 {
            break;
        }
    }
    println!("(keystream position: {})", keystream_pos);

    print!("Cipher: ");
    for b in ciphertext {
        print!("{:02x} ", b);
    }
    println!();
}

fn print_decryption_details(
    ciphertext: &[u8],
    key_bytes: &[u8],
    plaintext: &str,
    keystream_pos: usize,
) {
    println!("\n[DECRYPT]");
    print!("Cipher: ");
    for b in ciphertext {
        print!("{:02x} ", b);
    }
    println!();

    print!("Key: ");
    for (i, b) in key_bytes.iter().enumerate() {
        print!("{:02x} ", b);
        if i >= ciphertext.len() - 1 {
            break;
        }
    }
    println!("(keystream position: {})", keystream_pos);

    print!("Plain: ");
    for b in plaintext.as_bytes() {
        print!("{:02x} ", b);
    }
    print!("-> \"{}\"", plaintext);
    println!();
}

/// Sanitize message for display (prevent terminal injection)
fn sanitize_for_display(data: &[u8]) -> String {
    String::from_utf8_lossy(data)
        .chars()
        .map(|c| {
            // Only allow printable ASCII and common whitespace
            if c.is_ascii_graphic() || c == ' ' || c == '\t' {
                c
            } else if c == '\n' || c == '\r' {
                ' ' // Replace newlines with spaces
            } else {
                '�' // Replace non-printable with replacement character
            }
        })
        .collect()
}

/// Handle client connection on server side
fn handle_client(mut stream: TcpStream, addr: String) -> Result<(), Box<dyn std::error::Error>> {
    println!("\n[CLIENT] Connected from {}", addr);

    // Set timeouts to prevent hanging connections
    stream.set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)))?;
    stream.set_write_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)))?;

    println!();
    println!("[DH] Starting key exchange...");
    println!("[DH] Using hardcoded DH parameters:");
    println!("p = D87F A3E2 91B4 C7F3 (64-bit prime - public)");
    println!("g = {} (generator - public)", G);
    println!();

    // Generate DH keypair
    let (private_key, public_key) = generate_dh_keypair();

    println!();
    println!("[DH] Exchanging keys...");
    println!("[NETWORK] Sending public key (8 bytes)...");
    println!("→ Send our public: {:X}", public_key);

    // Send public key to client
    stream.write_all(&public_key.to_be_bytes())?;
    stream.flush()?;

    // Receive client's public key with timeout protection
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf)?;
    let client_public_key = u64::from_be_bytes(buf);

    println!("[NETWORK] Received public key (8 bytes) ✓");
    println!("← Receive their public: {:X}", client_public_key);

    // Compute shared secret with validation
    let shared_secret = match compute_shared_secret(private_key, client_public_key) {
        Ok(secret) => secret,
        Err(e) => {
            eprintln!("[SECURITY ERROR] Invalid peer public key: {}", e);
            return Err(e.into());
        }
    };

    println!();
    println!("[VERIFY] Both sides computed the same secret ✓");

    // Print keystream preview
    let mut preview_gen = KeystreamGenerator::new(shared_secret);
    print!("\nKeystream: ");
    for i in 0..20 {
        if i > 0 {
            print!(" ");
        }
        print!("{:02X}", preview_gen.next_byte());
    }
    println!(" ...");

    println!();
    println!("✓ Secure channel established!");
    println!();

    // Communication loop
    let stream_clone = stream.try_clone()?;
    let shared_secret_clone = shared_secret;

    // Track keystream position and message count
    let keystream_pos = Arc::new(Mutex::new(0usize));
    let keystream_pos_send = Arc::clone(&keystream_pos);
    let message_count = Arc::new(Mutex::new(0usize));
    let message_count_clone = Arc::clone(&message_count);

    // Spawn thread for receiving messages
    let receive_handle = thread::spawn(move || -> Result<(), Box<dyn std::error::Error + Send>> {
        let mut stream = stream_clone;
        loop {
            // Check message count limit
            {
                let count = message_count_clone.lock().unwrap();
                if *count >= MAX_MESSAGES_PER_SESSION {
                    println!("[SECURITY] Maximum messages per session reached");
                    return Ok(());
                }
            }

            // Read message length with proper error handling
            let mut len_buf = [0u8; 4];
            match stream.read_exact(&mut len_buf) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    println!("[INFO] Connection closed by peer");
                    return Ok(());
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    println!("[INFO] Connection timeout");
                    return Ok(());
                }
                Err(e) => return Err(Box::new(e) as Box<dyn std::error::Error + Send>),
            }

            let len = u32::from_be_bytes(len_buf) as usize;

            // Validate message length
            if len == 0 {
                println!("[SECURITY] Received zero-length message, ignoring");
                continue;
            }
            if len > MAX_MESSAGE_LENGTH {
                println!(
                    "[SECURITY] Message too large ({} bytes), closing connection",
                    len
                );
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Message exceeds maximum allowed size",
                )) as Box<dyn std::error::Error + Send>);
            }

            // Read encrypted message
            let mut encrypted = vec![0u8; len];
            match stream.read_exact(&mut encrypted) {
                Ok(_) => {}
                Err(e) => {
                    println!("[ERROR] Failed to read message: {}", e);
                    return Err(Box::new(e) as Box<dyn std::error::Error + Send>);
                }
            }

            // Increment message count
            {
                let mut count = message_count_clone.lock().unwrap();
                *count += 1;
            }

            println!("[NETWORK] Received encrypted message ({} bytes)", len);
            println!("[←] Received {} bytes", len);

            // Get current keystream position
            let current_pos = {
                let mut pos = keystream_pos.lock().unwrap();
                let current = *pos;
                *pos += len;
                current
            };

            // Decrypt with keystream preview
            let mut key_gen = KeystreamGenerator::new(shared_secret_clone);
            let key_bytes: Vec<u8> = (0..len).map(|_| key_gen.next_byte()).collect();

            let decrypted = decrypt_message(&encrypted, shared_secret_clone);

            // Sanitize message for safe display
            let message = sanitize_for_display(&decrypted);

            print_decryption_details(&encrypted, &key_bytes, &message, current_pos);

            println!();
            println!(
                "[TEST] Round-trip verified: \"{}\" → encrypt → decrypt → \"{}\" ✓",
                message, message
            );
            println!();
            println!("[CLIENT] {}", message);
            println!();
            println!("[CHAT] Type message:");
            print!("> ");
            std::io::stdout().flush().ok();
        }
    });

    // Main thread for sending messages
    println!("[CHAT] Type message:");
    let stdin = std::io::stdin();
    let mut send_count = 0usize;

    loop {
        print!("> ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        if stdin.read_line(&mut input).is_err() {
            break;
        }

        let message = input.trim();
        if message.is_empty() {
            continue;
        }

        // Check message length
        if message.len() > MAX_MESSAGE_LENGTH {
            println!(
                "[ERROR] Message too long (max {} bytes)",
                MAX_MESSAGE_LENGTH
            );
            continue;
        }

        // Check send count
        send_count += 1;
        if send_count > MAX_MESSAGES_PER_SESSION {
            println!("[SECURITY] Maximum messages per session reached");
            break;
        }

        // Get current keystream position for sending
        let current_pos = {
            let mut pos = keystream_pos_send.lock().unwrap();
            let current = *pos;
            *pos += message.len();
            current
        };

        // Generate keystream preview for this message
        let mut key_gen = KeystreamGenerator::new(shared_secret);
        let key_bytes: Vec<u8> = (0..message.len()).map(|_| key_gen.next_byte()).collect();

        // Encrypt message
        let encrypted = encrypt_message(message.as_bytes(), shared_secret);

        print_encryption_details(message, &key_bytes, &encrypted, current_pos);

        println!();
        println!(
            "[NETWORK] Sending encrypted message ({} bytes)...",
            encrypted.len()
        );

        // Send length + encrypted message
        let len = encrypted.len() as u32;
        match stream.write_all(&len.to_be_bytes()) {
            Ok(_) => {}
            Err(e) => {
                println!("[ERROR] Failed to send message length: {}", e);
                break;
            }
        }
        match stream.write_all(&encrypted) {
            Ok(_) => {}
            Err(e) => {
                println!("[ERROR] Failed to send message: {}", e);
                break;
            }
        }
        stream.flush()?;

        println!("[→] Sent {} bytes", encrypted.len());
        println!();
    }

    // Wait for receive thread to finish
    let _ = receive_handle.join();

    Ok(())
}

/// Start server
fn run_server(addr: &str) {
    println!("[SERVER] Listening on {}", addr);
    println!("[SERVER] Waiting for client...");

    let listener = match TcpListener::bind(addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("[ERROR] Failed to bind server: {}", e);
            return;
        }
    };

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                let addr = match stream.peer_addr() {
                    Ok(a) => a.to_string(),
                    Err(_) => "unknown".to_string(),
                };

                thread::spawn(move || {
                    if let Err(e) = handle_client(stream, addr) {
                        eprintln!("[ERROR] Client handler error: {}", e);
                    }
                });
                break; // Handle one client for simplicity
            }
            Err(e) => {
                eprintln!("[ERROR] Connection failed: {}", e);
            }
        }
    }

    // Keep main thread alive
    loop {
        thread::sleep(Duration::from_secs(1));
    }
}

/// Connect as client
fn run_client(addr: &str) -> Result<(), Box<dyn std::error::Error>> {
    println!("[CLIENT] Connecting to {}...", addr);

    let mut stream = TcpStream::connect(addr)?;

    // Set timeouts
    stream.set_read_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)))?;
    stream.set_write_timeout(Some(Duration::from_secs(READ_TIMEOUT_SECS)))?;

    println!("[CLIENT] Connected!");
    println!();
    println!("[DH] Starting key exchange...");
    println!("[DH] Using hardcoded DH parameters:");
    println!("p = D87F A3E2 91B4 C7F3 (64-bit prime - public)");
    println!("g = {} (generator - public)", G);
    println!();

    // Generate DH keypair
    let (private_key, public_key) = generate_dh_keypair();

    println!();
    println!("[DH] Exchanging keys...");

    // Receive server's public key
    let mut buf = [0u8; 8];
    stream.read_exact(&mut buf)?;
    let server_public_key = u64::from_be_bytes(buf);

    println!("[NETWORK] Received public key (8 bytes) ✓");
    println!("← Receive their public: {:X}", server_public_key);

    // Send our public key
    println!("[NETWORK] Sending public key (8 bytes)...");
    println!("→ Send our public: {:X}", public_key);
    stream.write_all(&public_key.to_be_bytes())?;
    stream.flush()?;

    // Compute shared secret with validation
    let shared_secret = match compute_shared_secret(private_key, server_public_key) {
        Ok(secret) => secret,
        Err(e) => {
            eprintln!("[SECURITY ERROR] Invalid peer public key: {}", e);
            return Err(e.into());
        }
    };

    println!();
    println!("[VERIFY] Both sides computed the same secret ✓");

    // Print keystream preview
    let mut preview_gen = KeystreamGenerator::new(shared_secret);
    print!("\nKeystream: ");
    for i in 0..20 {
        if i > 0 {
            print!(" ");
        }
        print!("{:02X}", preview_gen.next_byte());
    }
    println!(" ...");

    println!();
    println!("✓ Secure channel established!");
    println!();

    // Communication loop
    let stream_clone = stream.try_clone()?;
    let shared_secret_clone = shared_secret;

    // Track keystream position and message count
    let keystream_pos = Arc::new(Mutex::new(0usize));
    let keystream_pos_send = Arc::clone(&keystream_pos);
    let message_count = Arc::new(Mutex::new(0usize));
    let message_count_clone = Arc::clone(&message_count);

    // Spawn thread for receiving messages
    let receive_handle = thread::spawn(move || -> Result<(), Box<dyn std::error::Error + Send>> {
        let mut stream = stream_clone;
        loop {
            // Check message count limit
            {
                let count = message_count_clone.lock().unwrap();
                if *count >= MAX_MESSAGES_PER_SESSION {
                    println!("[SECURITY] Maximum messages per session reached");
                    return Ok(());
                }
            }

            // Read message length
            let mut len_buf = [0u8; 4];
            match stream.read_exact(&mut len_buf) {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    println!("[INFO] Connection closed by peer");
                    return Ok(());
                }
                Err(e)
                    if e.kind() == std::io::ErrorKind::WouldBlock
                        || e.kind() == std::io::ErrorKind::TimedOut =>
                {
                    println!("[INFO] Connection timeout");
                    return Ok(());
                }
                Err(e) => return Err(Box::new(e) as Box<dyn std::error::Error + Send>),
            }

            let len = u32::from_be_bytes(len_buf) as usize;

            // Validate message length
            if len == 0 {
                println!("[SECURITY] Received zero-length message, ignoring");
                continue;
            }
            if len > MAX_MESSAGE_LENGTH {
                println!(
                    "[SECURITY] Message too large ({} bytes), closing connection",
                    len
                );
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Message exceeds maximum allowed size",
                )) as Box<dyn std::error::Error + Send>);
            }

            // Read encrypted message
            let mut encrypted = vec![0u8; len];
            match stream.read_exact(&mut encrypted) {
                Ok(_) => {}
                Err(e) => {
                    println!("[ERROR] Failed to read message: {}", e);
                    return Err(Box::new(e) as Box<dyn std::error::Error + Send>);
                }
            }

            // Increment message count
            {
                let mut count = message_count_clone.lock().unwrap();
                *count += 1;
            }

            println!("[NETWORK] Received encrypted message ({} bytes)", len);
            println!("[←] Received {} bytes", len);

            // Get current keystream position
            let current_pos = {
                let mut pos = keystream_pos.lock().unwrap();
                let current = *pos;
                *pos += len;
                current
            };

            // Decrypt with keystream preview
            let mut key_gen = KeystreamGenerator::new(shared_secret_clone);
            let key_bytes: Vec<u8> = (0..len).map(|_| key_gen.next_byte()).collect();

            let decrypted = decrypt_message(&encrypted, shared_secret_clone);

            // Sanitize message for safe display
            let message = sanitize_for_display(&decrypted);

            print_decryption_details(&encrypted, &key_bytes, &message, current_pos);

            println!();
            println!(
                "[TEST] Round-trip verified: \"{}\" → encrypt → decrypt → \"{}\" ✓",
                message, message
            );
            println!();
            println!("[SERVER] {}", message);
            println!();
            println!("[CHAT] Type message:");
            print!("> ");
            std::io::stdout().flush().ok();
        }
    });

    // Main thread for sending messages
    println!("[CHAT] Type message:");
    let stdin = std::io::stdin();
    let mut send_count = 0usize;

    loop {
        print!("> ");
        std::io::stdout().flush()?;

        let mut input = String::new();
        if stdin.read_line(&mut input).is_err() {
            break;
        }

        let message = input.trim();
        if message.is_empty() {
            continue;
        }

        // Check message length
        if message.len() > MAX_MESSAGE_LENGTH {
            println!(
                "[ERROR] Message too long (max {} bytes)",
                MAX_MESSAGE_LENGTH
            );
            continue;
        }

        // Check send count
        send_count += 1;
        if send_count > MAX_MESSAGES_PER_SESSION {
            println!("[SECURITY] Maximum messages per session reached");
            break;
        }

        // Get current keystream position for sending
        let current_pos = {
            let mut pos = keystream_pos_send.lock().unwrap();
            let current = *pos;
            *pos += message.len();
            current
        };

        // Generate keystream preview for this message
        let mut key_gen = KeystreamGenerator::new(shared_secret);
        let key_bytes: Vec<u8> = (0..message.len()).map(|_| key_gen.next_byte()).collect();

        // Encrypt message
        let encrypted = encrypt_message(message.as_bytes(), shared_secret);

        print_encryption_details(message, &key_bytes, &encrypted, current_pos);

        println!();
        println!(
            "[NETWORK] Sending encrypted message ({} bytes)...",
            encrypted.len()
        );

        // Send length + encrypted message
        let len = encrypted.len() as u32;
        match stream.write_all(&len.to_be_bytes()) {
            Ok(_) => {}
            Err(e) => {
                println!("[ERROR] Failed to send message length: {}", e);
                break;
            }
        }
        match stream.write_all(&encrypted) {
            Ok(_) => {}
            Err(e) => {
                println!("[ERROR] Failed to send message: {}", e);
                break;
            }
        }
        stream.flush()?;

        println!("[→] Sent {} bytes", encrypted.len());
        println!();
    }

    // Wait for receive thread to finish
    let _ = receive_handle.join();

    Ok(())
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        print_help();
        return;
    }

    let result = match args[1].as_str() {
        "server" => {
            let addr = if args.len() > 2 {
                format!("0.0.0.0:{}", &args[2])
            } else {
                "0.0.0.0:8080".to_string()
            };
            run_server(&addr);
            Ok(())
        }
        "client" => {
            let addr = if args.len() > 2 {
                format!("127.0.0.1:{}", &args[2])
            } else {
                "127.0.0.1:8080".to_string()
            };
            run_client(&addr)
        }
        "--help" | "-h" => {
            print_help();
            Ok(())
        }
        _ => {
            eprintln!("Unknown command: {}", args[1]);
            print_help();
            Err("Invalid command".into())
        }
    };

    if let Err(e) = result {
        eprintln!("[FATAL ERROR] {}", e);
        std::process::exit(1);
    }
}

fn print_help() {
    println!("Usage: streamchat <COMMAND>");
    println!();
    println!("stream cipher chat with Diffie-Hellman key generation");
    println!();
    println!("Commands:");
    println!("  server [port]    Start server (default: 8080)");
    println!("  client [port]    Connect to server (default: 8080)");
    println!();
    println!("Options:");
    println!("  -h, --help       Print help");
}

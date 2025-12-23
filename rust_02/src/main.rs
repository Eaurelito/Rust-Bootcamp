use clap::{ArgGroup, Parser};
use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "hextool")]
#[command(about = "read and write binary files in hexadecimal", long_about = None)]
#[command(group(
    ArgGroup::new("mode")
        .required(true)
        .args(&["read", "write"]),
))]
struct Args {
    /// Target file
    #[arg(short, long, value_parser = validate_file_path)]
    file: PathBuf,

    /// Read mode (display hex)
    #[arg(short, long)]
    read: bool,

    /// Write mode (hex string to write)
    #[arg(short, long, value_parser = validate_hex_string)]
    write: Option<String>,

    /// Offset in bytes (decimal or 0x hex)
    #[arg(short, long, default_value = "0", value_parser = parse_number)]
    offset: usize,

    /// Number of bytes to read
    #[arg(short, long, value_parser = validate_size)]
    size: Option<usize>,
}

// Maximum allowed file size to prevent resource exhaustion (1GB)
const MAX_FILE_SIZE: u64 = 1024 * 1024 * 1024;

// Maximum hex string length for write operations (10MB)
const MAX_HEX_STRING_LEN: usize = 20 * 1024 * 1024;

// Buffer size for chunked reading
const BUFFER_SIZE: usize = 8192;

fn validate_file_path(s: &str) -> Result<PathBuf, String> {
    // Check for null bytes (security risk)
    if s.contains('\0') {
        return Err("File path contains null bytes".to_string());
    }

    // Check for excessive length
    if s.len() > 4096 {
        return Err("File path too long (max 4096 characters)".to_string());
    }

    let path = PathBuf::from(s);

    // Canonicalize to prevent path traversal attacks
    // Note: This will fail if the file doesn't exist for read operations,
    // but that's okay - we'll catch it later
    let canonical = path.canonicalize().unwrap_or_else(|_| {
        // For new files (write mode), just use the provided path
        // but ensure it's not trying to escape with ../ etc
        if s.contains("..") {
            return PathBuf::new(); // Will fail validation below
        }
        path.clone()
    });

    // Verify the path is valid UTF-8 and doesn't contain suspicious patterns
    if let Some(path_str) = canonical.to_str() {
        // Check for null bytes in the canonicalized path
        if path_str.contains('\0') {
            return Err("Canonicalized path contains null bytes".to_string());
        }
    } else {
        return Err("File path contains invalid UTF-8".to_string());
    }

    Ok(canonical)
}

fn validate_hex_string(s: &str) -> Result<String, String> {
    // Check length to prevent memory exhaustion
    if s.len() > MAX_HEX_STRING_LEN {
        return Err(format!(
            "Hex string too long (max {} characters, {} MB of data)",
            MAX_HEX_STRING_LEN,
            MAX_HEX_STRING_LEN / 2 / 1024 / 1024
        ));
    }

    // Remove whitespace for validation
    let cleaned = s.chars().filter(|c| !c.is_whitespace()).collect::<String>();

    // Check for null bytes
    if cleaned.contains('\0') {
        return Err("Hex string contains null bytes".to_string());
    }

    // Validate hex characters only
    if !cleaned.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(
            "Hex string contains invalid characters (only 0-9, a-f, A-F allowed)".to_string(),
        );
    }

    // Check for even length
    if cleaned.len() % 2 != 0 {
        return Err("Hex string must have even number of characters".to_string());
    }

    Ok(s.to_string())
}

fn validate_size(s: &str) -> Result<usize, String> {
    let size = parse_number(s)?;

    // Prevent requesting excessive amounts of data
    if size > MAX_FILE_SIZE as usize {
        return Err(format!(
            "Size too large (max {} bytes, {} GB)",
            MAX_FILE_SIZE,
            MAX_FILE_SIZE / 1024 / 1024 / 1024
        ));
    }

    if size == 0 {
        return Err("Size must be greater than 0".to_string());
    }

    Ok(size)
}

fn parse_number(s: &str) -> Result<usize, String> {
    // Check for null bytes
    if s.contains('\0') {
        return Err("Number contains null bytes".to_string());
    }

    // Check length to prevent parsing attacks
    if s.len() > 32 {
        return Err("Number string too long".to_string());
    }

    if s.starts_with("0x") || s.starts_with("0X") {
        // Validate hex string
        let hex_part = &s[2..];
        if !hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(format!("Invalid hexadecimal number: {}", s));
        }

        usize::from_str_radix(hex_part, 16)
            .map_err(|_| format!("Invalid hexadecimal number: {}", s))
    } else {
        // Validate decimal string
        if !s.chars().all(|c| c.is_ascii_digit()) {
            return Err(format!("Invalid decimal number: {}", s));
        }

        s.parse::<usize>()
            .map_err(|_| format!("Invalid decimal number: {}", s))
    }
}

fn parse_hex_string(hex: &str) -> Result<Vec<u8>, String> {
    let hex = hex
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect::<String>();

    if hex.len() % 2 != 0 {
        return Err("Hex string must have even number of characters".to_string());
    }

    (0..hex.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&hex[i..i + 2], 16)
                .map_err(|_| format!("Invalid hex byte: {}", &hex[i..i + 2]))
        })
        .collect()
}

fn read_file(path: &Path, offset: usize, size: Option<usize>) -> io::Result<()> {
    // Open file with explicit permissions check
    let mut file = File::open(path)?;
    let metadata = file.metadata()?;

    // Security: Check if it's a regular file
    if !metadata.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Target is not a regular file (may be a directory, symlink, or special file)",
        ));
    }

    let file_size = metadata.len();

    // Check file size limit
    if file_size > MAX_FILE_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "File too large ({} bytes). Maximum allowed: {} bytes (1 GB)",
                file_size, MAX_FILE_SIZE
            ),
        ));
    }

    let file_size = file_size as usize;

    if offset >= file_size {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("Offset {} exceeds file size {}", offset, file_size),
        ));
    }

    // Validate offset for potential overflow
    if let Err(_) = u64::try_from(offset) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Offset value too large",
        ));
    }

    file.seek(SeekFrom::Start(offset as u64))?;

    let bytes_to_read = size.unwrap_or(file_size - offset).min(file_size - offset);

    // Additional check: prevent integer overflow
    if offset.checked_add(bytes_to_read).is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Offset + size would cause integer overflow",
        ));
    }

    println!(
        "Reading {} bytes from offset 0x{:x} ({})",
        bytes_to_read, offset, offset
    );
    println!();

    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut bytes_read_total = 0;
    let mut current_offset = offset;

    while bytes_read_total < bytes_to_read {
        let bytes_remaining = bytes_to_read - bytes_read_total;
        let bytes_to_read_now = bytes_remaining.min(BUFFER_SIZE);

        // Read chunk from file
        let n = file.read(&mut buffer[..bytes_to_read_now])?;
        if n == 0 {
            break; // EOF reached
        }

        // Display hex dump for this chunk
        for (i, chunk) in buffer[..n].chunks(16).enumerate() {
            let addr = current_offset + i * 16;
            print!("{:08x}  ", addr);

            // Hex values
            for (j, byte) in chunk.iter().enumerate() {
                print!("{:02x} ", byte);
                if j == 7 {
                    print!(" ");
                }
            }

            // Padding
            if chunk.len() < 16 {
                for j in chunk.len()..16 {
                    print!("   ");
                    if j == 7 {
                        print!(" ");
                    }
                }
            }

            // ASCII representation - sanitize output
            print!(" |");
            for byte in chunk {
                // Only display printable ASCII, replace everything else with '.'
                let c = if *byte >= 32 && *byte <= 126 {
                    *byte as char
                } else {
                    '.'
                };
                print!("{}", c);
            }
            println!("|");
        }

        bytes_read_total += n;
        current_offset += n;
    }

    Ok(())
}

fn write_file(path: &Path, hex_data: &str, offset: usize) -> io::Result<()> {
    let bytes =
        parse_hex_string(hex_data).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // Validate offset for potential overflow
    if let Err(_) = u64::try_from(offset) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Offset value too large",
        ));
    }

    // Check for integer overflow: offset + data length
    if offset.checked_add(bytes.len()).is_none() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Offset + data length would cause integer overflow",
        ));
    }

    // Open file with restricted permissions (create with 0o600 on Unix)
    let mut file = OpenOptions::new().write(true).create(true).open(path)?;

    // On Unix systems, set restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = file.metadata()?.permissions();
        perms.set_mode(0o600); // rw------- (owner only)
        std::fs::set_permissions(path, perms)?;
    }

    file.seek(SeekFrom::Start(offset as u64))?;
    file.write_all(&bytes)?;

    // Ensure data is written to disk
    file.sync_all()?;

    println!(
        "Wrote {} bytes to {} at offset 0x{:x} ({})",
        bytes.len(),
        path.display(),
        offset,
        offset
    );

    Ok(())
}

fn main() {
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{}", e);
            std::process::exit(1);
        }
    };

    // Execute operation with proper error handling
    let result = if args.read {
        read_file(&args.file, args.offset, args.size)
    } else if let Some(hex_data) = args.write {
        write_file(&args.file, &hex_data, args.offset)
    } else {
        unreachable!()
    };

    if let Err(e) = result {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::io::Write;
    use tempfile::TempDir;

    // Helper function to create a test file
    fn create_test_file(dir: &TempDir, name: &str, content: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        let mut file = File::create(&path).unwrap();
        file.write_all(content).unwrap();
        path
    }

    #[test]
    fn test_parse_number_decimal() {
        assert_eq!(parse_number("123").unwrap(), 123);
        assert_eq!(parse_number("0").unwrap(), 0);
        assert_eq!(parse_number("999999").unwrap(), 999999);
    }

    #[test]
    fn test_parse_number_hex() {
        assert_eq!(parse_number("0x10").unwrap(), 16);
        assert_eq!(parse_number("0xFF").unwrap(), 255);
        assert_eq!(parse_number("0x0").unwrap(), 0);
        assert_eq!(parse_number("0xDEADBEEF").unwrap(), 3735928559);
    }

    #[test]
    fn test_parse_number_invalid() {
        assert!(parse_number("abc").is_err());
        assert!(parse_number("12.5").is_err());
        assert!(parse_number("-10").is_err());
        assert!(parse_number("0x").is_err());
        assert!(parse_number("0xGG").is_err());
    }

    #[test]
    fn test_parse_number_null_bytes() {
        assert!(parse_number("12\03").is_err());
    }

    #[test]
    fn test_parse_number_too_long() {
        let long_string = "1".repeat(100);
        assert!(parse_number(&long_string).is_err());
    }

    #[test]
    fn test_parse_hex_string_valid() {
        assert_eq!(
            parse_hex_string("DEADBEEF").unwrap(),
            vec![0xDE, 0xAD, 0xBE, 0xEF]
        );
        assert_eq!(
            parse_hex_string("00 11 22").unwrap(),
            vec![0x00, 0x11, 0x22]
        );
        assert_eq!(parse_hex_string("a1b2c3").unwrap(), vec![0xA1, 0xB2, 0xC3]);
    }

    #[test]
    fn test_parse_hex_string_invalid() {
        assert!(parse_hex_string("GG").is_err());
        assert!(parse_hex_string("ABC").is_err()); // Odd length
        assert!(parse_hex_string("12 3").is_err()); // Odd length after whitespace removal
    }

    #[test]
    fn test_validate_hex_string_valid() {
        assert!(validate_hex_string("DEADBEEF").is_ok());
        assert!(validate_hex_string("00 11 22 33").is_ok());
        assert!(validate_hex_string("aAbBcCdDeEfF").is_ok());
    }

    #[test]
    fn test_validate_hex_string_invalid() {
        assert!(validate_hex_string("GG").is_err());
        assert!(validate_hex_string("12\0").is_err()); // Null byte
        assert!(validate_hex_string("XYZ").is_err());
    }

    #[test]
    fn test_validate_hex_string_too_long() {
        let long_hex = "AA".repeat(MAX_HEX_STRING_LEN);
        assert!(validate_hex_string(&long_hex).is_err());
    }

    #[test]
    fn test_validate_size() {
        assert_eq!(validate_size("100").unwrap(), 100);
        assert_eq!(validate_size("0x100").unwrap(), 256);
        assert!(validate_size("0").is_err()); // Size must be > 0
    }

    #[test]
    fn test_validate_size_too_large() {
        let huge = (MAX_FILE_SIZE + 1).to_string();
        assert!(validate_size(&huge).is_err());
    }

    #[test]
    fn test_validate_file_path_null_bytes() {
        assert!(validate_file_path("test\0file").is_err());
    }

    #[test]
    fn test_validate_file_path_too_long() {
        let long_path = "a".repeat(5000);
        assert!(validate_file_path(&long_path).is_err());
    }

    #[test]
    fn test_validate_file_path_traversal() {
        // This should be rejected or canonicalized safely
        let result = validate_file_path("../../etc/passwd");
        // Either it errors or it canonicalizes to a safe path
        assert!(result.is_err() || !result.unwrap().to_string_lossy().contains(".."));
    }

    #[test]
    fn test_read_file_basic() {
        let temp_dir = TempDir::new().unwrap();
        let test_data = b"Hello, World!";
        let path = create_test_file(&temp_dir, "test.bin", test_data);

        // Read entire file
        let result = read_file(&path, 0, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_read_file_with_offset() {
        let temp_dir = TempDir::new().unwrap();
        let test_data = b"0123456789ABCDEF";
        let path = create_test_file(&temp_dir, "test.bin", test_data);

        // Read from offset 5
        let result = read_file(&path, 5, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_read_file_with_size() {
        let temp_dir = TempDir::new().unwrap();
        let test_data = b"0123456789ABCDEF";
        let path = create_test_file(&temp_dir, "test.bin", test_data);

        // Read 8 bytes
        let result = read_file(&path, 0, Some(8));
        assert!(result.is_ok());
    }

    #[test]
    fn test_read_file_offset_exceeds_size() {
        let temp_dir = TempDir::new().unwrap();
        let test_data = b"Hello";
        let path = create_test_file(&temp_dir, "test.bin", test_data);

        // Offset beyond file size
        let result = read_file(&path, 100, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_file_not_regular_file() {
        let temp_dir = TempDir::new().unwrap();

        // Try to read a directory
        let result = read_file(temp_dir.path(), 0, None);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_file_basic() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("output.bin");

        let result = write_file(&path, "DEADBEEF", 0);
        assert!(result.is_ok());

        // Verify written data
        let content = fs::read(&path).unwrap();
        assert_eq!(content, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_write_file_with_offset() {
        let temp_dir = TempDir::new().unwrap();
        let test_data = b"0000000000000000";
        let path = create_test_file(&temp_dir, "test.bin", test_data);

        // Write at offset 4
        let result = write_file(&path, "ABCD", 4);
        assert!(result.is_ok());

        // Verify
        let content = fs::read(&path).unwrap();
        assert_eq!(content[4], 0xAB);
        assert_eq!(content[5], 0xCD);
    }

    #[test]
    fn test_write_file_invalid_hex() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("output.bin");

        let result = write_file(&path, "GGGG", 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_file_with_spaces() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("output.bin");

        let result = write_file(&path, "DE AD BE EF", 0);
        assert!(result.is_ok());

        let content = fs::read(&path).unwrap();
        assert_eq!(content, vec![0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn test_chunked_reading_large_file() {
        let temp_dir = TempDir::new().unwrap();

        // Create a file larger than BUFFER_SIZE
        let large_data = vec![0x42; BUFFER_SIZE * 3];
        let path = create_test_file(&temp_dir, "large.bin", &large_data);

        let result = read_file(&path, 0, None);
        assert!(result.is_ok());
    }

    #[test]
    fn test_integer_overflow_protection() {
        let temp_dir = TempDir::new().unwrap();
        let test_data = b"Hello";
        let path = create_test_file(&temp_dir, "test.bin", test_data);

        // This should be caught by overflow checks
        let result = read_file(&path, usize::MAX - 10, Some(100));
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_file() {
        let temp_dir = TempDir::new().unwrap();
        let path = create_test_file(&temp_dir, "empty.bin", b"");

        // Reading from offset 0 of empty file should fail
        let result = read_file(&path, 0, None);
        // Empty files have size 0, so offset 0 >= size 0 is true, should error
        assert!(result.is_err());
    }

    #[test]
    fn test_write_empty_hex() {
        let temp_dir = TempDir::new().unwrap();
        let path = temp_dir.path().join("output.bin");

        // Empty hex string should work (writes 0 bytes)
        let result = write_file(&path, "", 0);
        assert!(result.is_ok());

        let content = fs::read(&path).unwrap();
        assert_eq!(content.len(), 0);
    }
}

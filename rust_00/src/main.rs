use clap::Parser;
use std::process;

/// A simple greeting program
#[derive(Parser)]
#[command(name = "Hello")]
#[command(about = "Greets a person", long_about = None)]
struct Args {
    /// Name to greet
    #[arg(default_value = "World", value_parser = validate_name)]
    name: String,

    /// Convert to uppercase
    #[arg(long)]
    upper: bool,

    /// Repeat greeting N times
    #[arg(long, default_value_t = 1, value_parser = validate_repeat)]
    repeat: usize,
}

/// Validates the name input to prevent security issues
fn validate_name(s: &str) -> Result<String, String> {
    // Check for empty input after trimming
    let trimmed = s.trim();
    if trimmed.is_empty() {
        return Err("Name cannot be empty or only whitespace".to_string());
    }

    // Check maximum length to prevent DoS attacks
    const MAX_LENGTH: usize = 100;
    if trimmed.len() > MAX_LENGTH {
        return Err(format!("Name too long (max {} characters)", MAX_LENGTH));
    }

    // Check for null bytes (potential injection attacks)
    if trimmed.contains('\0') {
        return Err("Name cannot contain null bytes".to_string());
    }

    // Check for control characters that could cause terminal issues
    if trimmed.chars().any(|c| c.is_control() && c != '\t') {
        return Err("Name cannot contain control characters".to_string());
    }

    // Check for shell metacharacters that could be dangerous
    const DANGEROUS_CHARS: &[char] = &[
        '$', '`', '|', ';', '&', '>', '<', '(', ')', '{', '}', '[', ']', '\\', '\r',
    ];
    if trimmed.chars().any(|c| DANGEROUS_CHARS.contains(&c)) {
        return Err("Name contains invalid characters".to_string());
    }

    // Only allow printable ASCII and common Unicode letters/spaces
    if !trimmed.chars().all(|c| {
        c.is_alphabetic()
            || c.is_numeric()
            || c == ' '
            || c == '-'
            || c == '\''
            || c == '.'
            || c == '_'
    }) {
        return Err("Name can only contain letters, numbers, spaces, hyphens, apostrophes, dots, and underscores".to_string());
    }

    Ok(trimmed.to_string())
}

/// Validates the repeat count to prevent resource exhaustion
fn validate_repeat(s: &str) -> Result<usize, String> {
    const MAX_REPEAT: usize = 1000;

    match s.parse::<usize>() {
        Ok(n) if n == 0 => Err("Repeat count must be at least 1".to_string()),
        Ok(n) if n > MAX_REPEAT => Err(format!("Repeat count too high (max {})", MAX_REPEAT)),
        Ok(n) => Ok(n),
        Err(_) => Err("Invalid repeat count".to_string()),
    }
}

fn main() {
    // Parse arguments and handle errors gracefully
    let args = match Args::try_parse() {
        Ok(args) => args,
        Err(e) => {
            eprintln!("{}", e);
            process::exit(1);
        }
    };

    // Sanitize the name further by removing any potential ANSI escape sequences
    let sanitized_name = sanitize_output(&args.name);

    // Create the greeting with controlled formatting
    let greeting = create_greeting(&sanitized_name, args.upper);

    // Output the greeting safely
    for i in 0..args.repeat {
        // Check for potential issues during output
        if let Err(e) = std::io::Write::write_all(&mut std::io::stdout(), greeting.as_bytes()) {
            eprintln!("Error writing output: {}", e);
            process::exit(1);
        }

        // Add newline except potentially after last iteration for cleaner output
        if i < args.repeat - 1 || args.repeat == 1 {
            println!();
        }
    }
}

/// Sanitizes output to prevent ANSI escape sequence injection
fn sanitize_output(s: &str) -> String {
    s.chars()
        .filter(|&c| c != '\x1b') // Remove ESC character
        .collect()
}

/// Creates the greeting message with proper escaping
fn create_greeting(name: &str, uppercase: bool) -> String {
    let greeting = format!("Hello {}", name);

    if uppercase {
        greeting.to_uppercase()
    } else {
        greeting
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_names() {
        assert!(validate_name("John").is_ok());
        assert!(validate_name("Mary Jane").is_ok());
        assert!(validate_name("O'Brien").is_ok());
        assert!(validate_name("Jean-Paul").is_ok());
        assert!(validate_name("Dr. Smith").is_ok());
    }

    #[test]
    fn test_invalid_names() {
        assert!(validate_name("").is_err());
        assert!(validate_name("   ").is_err());
        assert!(validate_name("John; rm -rf /").is_err());
        assert!(validate_name("$(whoami)").is_err());
        assert!(validate_name("test\0null").is_err());
        assert!(validate_name("test\ninjection").is_err());
    }

    #[test]
    fn test_repeat_validation() {
        assert!(validate_repeat("1").is_ok());
        assert!(validate_repeat("100").is_ok());
        assert!(validate_repeat("0").is_err());
        assert!(validate_repeat("10000").is_err());
        assert!(validate_repeat("-1").is_err());
    }

    #[test]
    fn test_sanitize_output() {
        assert_eq!(sanitize_output("Hello\x1b[31m"), "Hello[31m");
        assert_eq!(sanitize_output("Normal"), "Normal");
    }
}

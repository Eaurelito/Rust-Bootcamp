use clap::Parser;
use std::collections::HashMap;
use std::io::{self, Read};
use std::path::PathBuf;
use std::fs;

#[derive(Debug)]
enum WordFreqError {
    IoError(io::Error),
    InvalidInput(String),
    ArgumentError(String),
}

impl std::fmt::Display for WordFreqError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WordFreqError::IoError(e) => write!(f, "IO error: {}", e),
            WordFreqError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            WordFreqError::ArgumentError(msg) => write!(f, "Argument error: {}", msg),
        }
    }
}

impl From<io::Error> for WordFreqError {
    fn from(error: io::Error) -> Self {
        WordFreqError::IoError(error)
    }
}

type Result<T> = std::result::Result<T, WordFreqError>;

#[derive(Parser)]
#[command(name = "wordfreq")]
#[command(about = "Count word frequency in text.", long_about = None)]
struct Cli {
    /// Text to analyse (or use stdin)
    text: Option<String>,

    /// Show top N words
    #[arg(long, default_value_t = 10)]
    #[arg(value_parser = validate_positive_number)]
    top: usize,

    /// Ignore words shorter than N
    #[arg(long, default_value_t = 1)]
    #[arg(value_parser = validate_positive_number)]
    min_length: usize,

    /// Case insensitive counting
    #[arg(long)]
    ignore_case: bool,
}

fn validate_positive_number(s: &str) -> std::result::Result<usize, String> {
    match s.parse::<usize>() {
        Ok(n) if n > 0 => Ok(n),
        Ok(_) => Err(String::from("Value must be greater than 0")),
        Err(_) => Err(String::from("Must be a valid positive number")),
    }
}

struct InputReader;

impl InputReader {
    const MAX_INPUT_SIZE: usize = 100 * 1024 * 1024; // 100 MB limit
    const STDIN_BUFFER_SIZE: usize = 8192;

    /// Read input from stdin with size limits and timeout considerations
    fn read_from_stdin() -> Result<String> {
        let mut buffer = String::new();
        let stdin = io::stdin();
        let mut handle = stdin.lock();
        
        // Read in chunks to avoid loading too much into memory at once
        let mut temp_buffer = vec![0u8; Self::STDIN_BUFFER_SIZE];
        let mut total_size = 0;

        loop {
            match handle.read(&mut temp_buffer)? {
                0 => break, // EOF
                n => {
                    total_size += n;
                    if total_size > Self::MAX_INPUT_SIZE {
                        return Err(WordFreqError::InvalidInput(
                            format!("Input exceeds maximum size of {} MB", Self::MAX_INPUT_SIZE / (1024 * 1024))
                        ));
                    }
                    buffer.push_str(&String::from_utf8_lossy(&temp_buffer[..n]));
                }
            }
        }

        Ok(buffer)
    }

    /// Validate and sanitize text input
    fn validate_text(text: &str) -> Result<()> {
        if text.len() > Self::MAX_INPUT_SIZE {
            return Err(WordFreqError::InvalidInput(
                format!("Text exceeds maximum size of {} MB", Self::MAX_INPUT_SIZE / (1024 * 1024))
            ));
        }

        // Check for null bytes which could indicate binary data
        if text.contains('\0') {
            return Err(WordFreqError::InvalidInput(
                "Input contains null bytes. Binary data is not supported.".to_string()
            ));
        }

        Ok(())
    }

    /// Get input from CLI argument or stdin
    fn get_input(text_arg: Option<String>) -> Result<String> {
        let input = match text_arg {
            Some(text) => {
                Self::validate_text(&text)?;
                text
            }
            None => Self::read_from_stdin()?,
        };

        if input.trim().is_empty() {
            return Err(WordFreqError::InvalidInput(
                "No input provided or input is empty".to_string()
            ));
        }

        Ok(input)
    }
}
struct WordProcessor {
    ignore_case: bool,
    min_length: usize,
}

impl WordProcessor {
    const MAX_WORD_LENGTH: usize = 100; // Reasonable max for a word

    fn new(ignore_case: bool, min_length: usize) -> Self {
        Self { ignore_case, min_length }
    }

    /// Clean and normalize a word token
    fn clean_word(&self, word: &str) -> Option<String> {
        // Remove leading/trailing punctuation and whitespace
        let cleaned: String = word
            .chars()
            .filter(|c| c.is_alphanumeric() || *c == '\'' || *c == '-')
            .collect();

        // Skip if empty after cleaning
        if cleaned.is_empty() {
            return None;
        }

        // Validate word length
        if cleaned.len() > Self::MAX_WORD_LENGTH {
            // Skip extremely long tokens (likely not real words)
            return None;
        }

        // Apply case transformation if needed
        let processed = if self.ignore_case {
            cleaned.to_lowercase()
        } else {
            cleaned
        };

        // Apply minimum length filter
        if processed.len() >= self.min_length {
            Some(processed)
        } else {
            None
        }
    }

    /// Count word frequencies with proper error handling
    fn count_words(&self, input: &str) -> Result<HashMap<String, usize>> {
        let mut word_counts: HashMap<String, usize> = HashMap::new();
        let mut word_count = 0;
        const MAX_UNIQUE_WORDS: usize = 1_000_000; // Prevent excessive memory use

        for word in input.split_whitespace() {
            if let Some(cleaned) = self.clean_word(word) {
                *word_counts.entry(cleaned).or_insert(0) += 1;
                word_count += 1;

                // Prevent DoS through excessive unique words
                if word_counts.len() > MAX_UNIQUE_WORDS {
                    return Err(WordFreqError::InvalidInput(
                        format!("Too many unique words (>{} unique words). Input may be malformed.", MAX_UNIQUE_WORDS)
                    ));
                }
            }
        }

        if word_counts.is_empty() {
            return Err(WordFreqError::InvalidInput(
                "No valid words found in input after filtering".to_string()
            ));
        }

        Ok(word_counts)
    }
}
struct OutputFormatter;

impl OutputFormatter {
    fn format_results(word_counts: &HashMap<String, usize>, top: usize) -> Vec<(String, usize)> {
        let mut word_vec: Vec<_> = word_counts
            .iter()
            .map(|(word, count)| (word.clone(), *count))
            .collect();
        
        // Sort by frequency (descending), then alphabetically for ties
        word_vec.sort_by(|a, b| {
            b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0))
        });
        
        word_vec.into_iter().take(top).collect()
    }

    fn print_results(top_words: &[(String, usize)]) {
        if top_words.is_empty() {
            println!("No words to display.");
            return;
        }

        println!("Top {} words:", top_words.len());
        println!("{:<20} {}", "Word", "Count");
        println!("{}", "-".repeat(30));

        for (word, count) in top_words {
            // Truncate very long words for display
            let display_word = if word.len() > 20 {
                format!("{}...", &word[..17])
            } else {
                word.clone()
            };
            println!("{:<20} {}", display_word, count);
        }
    }
}

struct WordFrequencyApp {
    config: Cli,
}

impl WordFrequencyApp {
    fn new(config: Cli) -> Result<Self> {
        // Validate configuration
        if config.top == 0 {
            return Err(WordFreqError::ArgumentError(
                "Top value must be greater than 0".to_string()
            ));
        }

        if config.min_length > 50 {
            return Err(WordFreqError::ArgumentError(
                "Minimum length seems unreasonably high. Please use a value <= 50".to_string()
            ));
        }

        Ok(Self { config })
    }

    fn run(&self) -> Result<()> {
        // Get and validate input
        let input = InputReader::get_input(self.config.text.clone())?;

        // Process words
        let processor = WordProcessor::new(self.config.ignore_case, self.config.min_length);
        let word_counts = processor.count_words(&input)?;

        // Format and display results
        let top_words = OutputFormatter::format_results(&word_counts, self.config.top);
        OutputFormatter::print_results(&top_words);

        Ok(())
    }
}

fn main() {
    let cli = Cli::parse();

    match WordFrequencyApp::new(cli) {
        Ok(app) => {
            if let Err(e) = app.run() {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Configuration error: {}", e);
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_processor(ignore_case: bool, min_length: usize) -> WordProcessor {
        WordProcessor::new(ignore_case, min_length)
    }

    #[test]
    fn test_basic_word_counting() {
        let processor = create_processor(false, 1);
        let counts = processor.count_words("hello world hello").unwrap();
        
        assert_eq!(counts.get("hello"), Some(&2));
        assert_eq!(counts.get("world"), Some(&1));
        assert_eq!(counts.len(), 2);
    }

    #[test]
    fn test_case_sensitive() {
        let processor = create_processor(false, 1);
        let counts = processor.count_words("Hello hello HELLO").unwrap();
        
        assert_eq!(counts.get("Hello"), Some(&1));
        assert_eq!(counts.get("hello"), Some(&1));
        assert_eq!(counts.get("HELLO"), Some(&1));
        assert_eq!(counts.len(), 3);
    }

    #[test]
    fn test_case_insensitive() {
        let processor = create_processor(true, 1);
        let counts = processor.count_words("Hello hello HELLO").unwrap();
        
        assert_eq!(counts.get("hello"), Some(&3));
        assert_eq!(counts.len(), 1);
    }

    #[test]
    fn test_punctuation_removal() {
        let processor = create_processor(false, 1);
        let counts = processor.count_words("hello, world! hello.").unwrap();
        
        assert_eq!(counts.get("hello"), Some(&2));
        assert_eq!(counts.get("world"), Some(&1));
    }

    #[test]
    fn test_min_length_filter() {
        let processor = create_processor(false, 3);
        let counts = processor.count_words("a bb ccc dddd").unwrap();
        
        assert_eq!(counts.get("a"), None);
        assert_eq!(counts.get("bb"), None);
        assert_eq!(counts.get("ccc"), Some(&1));
        assert_eq!(counts.get("dddd"), Some(&1));
        assert_eq!(counts.len(), 2);
    }

    #[test]
    fn test_apostrophes_and_hyphens() {
        let processor = create_processor(false, 1);
        let counts = processor.count_words("don't it's well-known").unwrap();
        
        assert_eq!(counts.get("don't"), Some(&1));
        assert_eq!(counts.get("it's"), Some(&1));
        assert_eq!(counts.get("well-known"), Some(&1));
    }

    #[test]
    fn test_empty_input_error() {
        let processor = create_processor(false, 1);
        let result = processor.count_words("");
        
        assert!(result.is_err());
    }

    #[test]
    fn test_whitespace_only_error() {
        let processor = create_processor(false, 1);
        let result = processor.count_words("   \n\t  ");
        
        assert!(result.is_err());
    }

    #[test]
    fn test_no_valid_words_after_filtering() {
        let processor = create_processor(false, 10);
        let result = processor.count_words("a bb ccc");
        
        assert!(result.is_err());
    }

    #[test]
    fn test_null_byte_rejection() {
        let result = InputReader::validate_text("hello\0world");
        assert!(result.is_err());
    }

    #[test]
    fn test_output_sorting() {
        let processor = create_processor(false, 1);
        let counts = processor.count_words("a a a b b c").unwrap();
        let top = OutputFormatter::format_results(&counts, 10);
        
        assert_eq!(top.len(), 3);
        assert_eq!(top[0], ("a".to_string(), 3));
        assert_eq!(top[1], ("b".to_string(), 2));
        assert_eq!(top[2], ("c".to_string(), 1));
    }

    #[test]
    fn test_output_limiting() {
        let processor = create_processor(false, 1);
        let counts = processor.count_words("a a a b b c").unwrap();
        let top = OutputFormatter::format_results(&counts, 2);
        
        assert_eq!(top.len(), 2);
        assert_eq!(top[0], ("a".to_string(), 3));
        assert_eq!(top[1], ("b".to_string(), 2));
    }

    #[test]
    fn test_alphabetical_tie_breaking() {
        let processor = create_processor(false, 1);
        let counts = processor.count_words("zebra apple banana").unwrap();
        let top = OutputFormatter::format_results(&counts, 10);
        
        // All have count 1, should be alphabetically sorted
        assert_eq!(top[0].0, "apple");
        assert_eq!(top[1].0, "banana");
        assert_eq!(top[2].0, "zebra");
    }
}
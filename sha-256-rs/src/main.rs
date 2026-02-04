use sha_256_rs::{sha256, to_hex_string, Sha256};
use std::env;
use std::io::{self, Read};

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        print_usage();
        return;
    }

    match args[1].as_str() {
        "-s" | "--string" => {
            if args.len() < 3 {
                eprintln!("Error: No string provided");
                print_usage();
                return;
            }
            let input = args[2..].join(" ");
            let hash = sha256(input.as_bytes());
            println!("{}", to_hex_string(&hash));
        }
        "-f" | "--file" => {
            if args.len() < 3 {
                eprintln!("Error: No file path provided");
                print_usage();
                return;
            }
            let file_path = &args[2];
            match std::fs::read(file_path) {
                Ok(data) => {
                    let hash = sha256(&data);
                    println!("{}  {}", to_hex_string(&hash), file_path);
                }
                Err(e) => {
                    eprintln!("Error reading file '{}': {}", file_path, e);
                    std::process::exit(1);
                }
            }
        }
        "-i" | "--stdin" => {
            let mut buffer = Vec::new();
            match io::stdin().read_to_end(&mut buffer) {
                Ok(_) => {
                    let hash = sha256(&buffer);
                    println!("{}", to_hex_string(&hash));
                }
                Err(e) => {
                    eprintln!("Error reading from stdin: {}", e);
                    std::process::exit(1);
                }
            }
        }
        "--demo" => {
            run_demo();
        }
        "-h" | "--help" => {
            print_usage();
        }
        _ => {
            eprintln!("Error: Unknown option '{}'", args[1]);
            print_usage();
        }
    }
}

fn print_usage() {
    println!("SHA-256 Hash Generator");
    println!();
    println!("USAGE:");
    println!("    sha-256-rs [OPTIONS]");
    println!();
    println!("OPTIONS:");
    println!("    -s, --string <TEXT>    Hash a string");
    println!("    -f, --file <PATH>      Hash a file");
    println!("    -i, --stdin            Hash data from stdin");
    println!("    --demo                 Run demonstration with example inputs");
    println!("    -h, --help             Print this help message");
    println!();
    println!("EXAMPLES:");
    println!("    sha-256-rs -s \"hello world\"");
    println!("    sha-256-rs -f myfile.txt");
    println!("    echo \"test\" | sha-256-rs -i");
}

fn run_demo() {
    println!("=== SHA-256 Demo ===\n");

    let examples = vec![
        ("", "Empty string"),
        ("abc", "Simple text"),
        ("hello world", "Hello world"),
        ("The quick brown fox jumps over the lazy dog", "Pangram"),
    ];

    for (input, description) in examples {
        let hash = sha256(input.as_bytes());
        println!("Input: \"{}\"", input);
        println!("Description: {}", description);
        println!("SHA-256: {}", to_hex_string(&hash));
        println!();
    }

    println!("=== Incremental Hashing Demo ===\n");
    let mut hasher = Sha256::new();
    println!("Adding: \"hello\"");
    hasher.update(b"hello");
    println!("Adding: \" \"");
    hasher.update(b" ");
    println!("Adding: \"world\"");
    hasher.update(b"world");
    let hash = hasher.finalize();
    println!("Final hash: {}", to_hex_string(&hash));
}

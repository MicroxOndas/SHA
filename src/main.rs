// Code for the main function of the program

mod sha_lib;

use sha_lib::sha1;
use sha_lib::sha2;
use sha_lib::types;
use sha_lib::err_handling;


fn main() {
    menu();
}


fn menu() {
    'mainLoop: loop {
        println!();
        let mut option;
        let mut message;
        loop {
            println!("Welcome to Rust Hashing CLI");
            println!("1. SHA-1");
            println!("2. SHA-224");
            println!("3. SHA-256");
            println!("4. SHA-384");
            println!("5. SHA-512");
            println!("6. SHA-512/t");
            println!("7. Exit");
            print!("Select the algorithm you want to use: ");

            option = get_number();
            if (option < 7) & (option > 0) {
                print!("Enter the message you want to hash: ");
                message = get_user_input();
                break;
            } else if option == 7 {
                println!("Exiting...");
                break 'mainLoop;
            } else {
                println!("Invalid option");
            }
        }

        let hash = match option {
            1 => sha1::hash_message(&mut message,types::wrappers::ShaAlgorithm::SHA1),
            2 => sha2::hash_message(&mut message,types::wrappers::ShaAlgorithm::SHA224),
            3 => sha2::hash_message(&mut message,types::wrappers::ShaAlgorithm::SHA256),
            4 => sha2::hash_message(&mut message,types::wrappers::ShaAlgorithm::SHA384),
            5 => sha2::hash_message(&mut message,types::wrappers::ShaAlgorithm::SHA512),
            6 => {
                let mut t;
                loop{
                    print!("Enter the value of t: ");
                    t = get_number();
                    if (t >= 512) || (t < 1) || (t % 8 != 0) || (t == 384) {
                        println!("t must be a multiple of 8 and between 1 and 512");
                        continue;
                    } else {
                        break;
                    }
                    
                }
                sha2::hash_message(&mut message,types::wrappers::ShaAlgorithm::SHA512T(t))
            },
            _ => Err(err_handling::ShaError::InvalidAlgorithm),
        };
        let hash = match hash {
            Ok(h) => h,
            Err(e) => {
                println!("Error: {:?}",e);
                println!("Press any key to continue");
                get_user_input();
                clear_console();
                continue;
            },
        };
        println!("Hash value:\n{:x?}",hash.get_values().iter().map(|v| format!("{:x}",v)).collect::<String>());
        println!("Press any key to continue");
        get_user_input();
        clear_console();
    }
}

fn clear_console() {
    use std::io::Write;
    print!("\x1B[2J\x1B[H");
    std::io::stdout().flush().unwrap(); // Ensure the command is flushed immediately
}

fn get_user_input() -> String {
    use std::io::Write;
    std::io::stdout().flush().unwrap();
    let mut buf: String = String::new();
    std::io::stdin().read_line(&mut buf).expect("Unable to read line\n");
    let ret = buf.trim().to_string();
    buf.clear();
    ret
}

fn get_number() -> u16 {
    loop {
        let number = get_user_input().parse::<u16>();
        match number {
            Ok(n) => return n,
            Err(_) => println!("Invalid number"),
        }
    }
}

#[allow(dead_code)]
fn test() {
    let buf: &mut String = &mut (String::new());
    std::io::stdin().read_line(buf).expect("Unable to read line\n");
    let mut string = buf.trim().to_string();
    buf.clear();

    let hash = sha1::hash_message(&mut string,types::wrappers::ShaAlgorithm::SHA1);
    println!("{:x?}",hash);
    let hash = sha2::hash_message(&mut string,types::wrappers::ShaAlgorithm::SHA224);
    println!("{:x?}",hash);
    let hash = sha2::hash_message(&mut string,types::wrappers::ShaAlgorithm::SHA256);
    println!("{:x?}",hash);
    let hash = sha2::hash_message(&mut string,types::wrappers::ShaAlgorithm::SHA384);
    println!("{:x?}",hash);
    let hash = sha2::hash_message(&mut string,types::wrappers::ShaAlgorithm::SHA512);
    println!("{:x?}",hash);
    let hash = sha2::hash_message(&mut string,types::wrappers::ShaAlgorithm::SHA512T(224));
    println!("{:x?}",hash);
}

#[derive(Debug)]
pub enum MenuError {
    InvalidOption,
}


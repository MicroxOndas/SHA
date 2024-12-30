> [!NOTE] 
> This is in beta, therefore the code's structure as well as other details of it's implementation are subject to be revised.

# Rust CLI Hash Generator

A command-line interface (CLI) program written in Rust to generate cryptographic hashes using the **SHA-1** and **SHA-2** families of hashing algorithms. This program allows users to input data and generate secure hashes for a variety of purposes, including file verification, password storage, or general cryptographic needs.

---

## Features

- **Supported Algorithms**:
  - SHA-1
  - SHA-2 (SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/t)
- **Flexible Input**:
  - Accepts text input directly from the user.
  - Supports hashing the contents of files.
- **Cross-Platform**:
  - Runs on Windows, macOS, and Linux terminals.
- **Efficient and Secure**:
  - Implements the algorithms natively in Rust for performance and security.

---

## Installation

### Prerequisites

1. Install Rust and Cargo:
   - Follow the official guide: [Rust Installation](https://www.rust-lang.org/tools/install)

2. Clone the Repository:
   ```bash
   git clone https://github.com/your-username/rust-cli-hash-generator.git
   cd rust-cli-hash-generator
   ```

3. Build the project:
   ```bash
   cargo build --release
   ```

---

## Usage

### Run the Program

1. Execute the compiled binary:
   ```bash
   ./target/release/rust-cli-hash-generator
   ```

2. Follow the interactive prompts:
   - Enter a string or specify a file.
   - Select the desired hashing algorithm (e.g., SHA-1, SHA-256, etc.).
   - The program will display the computed hash.

### Examples

#### Generate a Hash from Text:
```bash
$ ./rust-cli-hash-generator
Welcome to the Rust Hash Generator!
Enter the text to hash: hello world
Select the algorithm (e.g., SHA1, SHA256): SHA256
Computed Hash: b94d27b9934d3e08a52e52d7da7dabfa9fcdff22d3a5da617d14e8f3d819a3a9
```

#### Generate a Hash from a File:
```bash
$ ./rust-cli-hash-generator
Welcome to the Rust Hash Generator!
Enter the path to the file: example.txt
Select the algorithm (e.g., SHA1, SHA256): SHA512
Computed Hash: 1e07be23c26a86ea37ea810c8ec7809352515a970e9253c26f5398b5b5dc44c0
```

---

## Development

### Folder Structure

- `src/`
  - `main.rs`: Entry point of the program.
  - `hashing/`: Contains the implementations of SHA-1 and SHA-2 algorithms.
  - `utils/`: Helper functions (e.g., file I/O, formatting).
- `Cargo.toml`: Rust project configuration.

### Run Tests
To ensure correctness, run the test suite:
```bash
cargo test
```

---

## Contributions

Contributions are welcome! Feel free to open issues or submit pull requests to improve the program or add new features.

1. Fork the repository.
2. Create a feature branch: `git checkout -b feature-new-algorithm`
3. Commit your changes: `git commit -m "Add new feature"`
4. Push to your branch: `git push origin feature-new-algorithm`
5. Open a pull request.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

---

## Acknowledgments

Special thanks to the Rust community for providing extensive documentation and libraries that made this project possible.

---

### Contact

For questions or feedback, contact [your-email@example.com](mailto:your-email@example.com).


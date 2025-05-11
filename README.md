# SHA256-BruteForce-With-Pthreads

Brute-force password cracking tool for SHA-256 hashes implemented in both sequential and parallel versions using Pthreads in C. This educational project demonstrates how multithreading can dramatically reduce execution time in cryptanalysis tasks by distributing the search space among multiple threads.

The project includes:
- sha256_seq.c – Sequential brute-force implementation
- sha256_pthread.c – Parallel brute-force implementation using Pthreads

##  Problem Description

The goal is to **recover a 5-character lowercase password** (e.g., `"abcde"`) by comparing its SHA-256 hash with generated candidates.

###  Constraints
- Passwords are exactly **5 characters long**
- Only lowercase letters `a-z` are used
- Hashing is done with **SHA-256**

##  How It Works

### Sequential Version (`sha256_seq.c`)
- Iterates through all 5-letter lowercase combinations (`a` to `z`)
- Hashes each candidate and compares it to the target hash
- Stops when the correct password is found

###  Parallel Version (`sha256_pthread.c`)
- Uses **Pthreads** to divide the search space
- Each thread is responsible for passwords starting with specific letters
- Threads terminate early if any of them finds the correct password
  
##  Compilation Instructions

###  Dependencies
- `gcc` compiler
- `libssl` for SHA-256 (`libssl-dev` on Linux)
- `pthread` library

###  Linux / macOS

```bash
# Compile sequential version
gcc sha256_seq.c -o sha256_seq -lssl -lcrypto

# Compile parallel version
gcc sha256_pthread.c -o sha256_pthread -lpthread -lssl -lcrypto

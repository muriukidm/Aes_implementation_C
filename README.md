# This is a AES 128 bit implementation in C. A unit test written in python is also implemented.

# Update [1] AES-128: Fixed test_rijndael.py to define TestRijndael and test aes_encrypt_block

# Update [2] AES-128: Added test_encrypt_decrypt.py to verify full encryption-decryption cycle

# Implementation

This is an implementation of the Advanced Encryption Standard (AES) algorithm. It provides a secure and efficient way to encrypt and decrypt data

The programming languages used in this implementation include
  Python
  C language

# Folder Structure

D:. rijndael starter code
│   .clang-format
│   .gitignore
│   .gitmodules
│   main.c
│   main.exe
│   main.o
│   Makefile
│   README.md
│   rijndael.c
│   rijndael.dll
│   rijndael.h
│   rijndael.o
│
├───.github
│   └───workflows
│           build.yml
│
├───.vscode
│       tasks.json
│
├───aes
│   │   .gitignore
│   │   aes.py
│   │   LICENSE
│   │   README.md
│   │   tests.py
│   │
│   └───__pycache__
│           aes.cpython-310.pyc
│
└───unit_tests
    │   test_encrypt_decrypt.py
    │   test_rijndael.py
    │
    └───__pycache__
            test_rijndael.cpython-310.pyc

# SubModule 

The python submodule offered at https://github.com/boppreh/aes/ was used to compare against the C implementation

# REFERENCES

The book Cryptography in C and C++ by Michael Welschenbach offered guidance in modular exponentiation and fundamental operations.


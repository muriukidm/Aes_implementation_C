# Import required modules for unit testing, C library interaction, and path handling
import unittest  # Framework for writing and running unit tests
import ctypes  # For interfacing with rijndael.dll (C implementation)
import os  # For path manipulation and random byte generation
import sys  # For modifying Python's module search path
from aes.aes import AES  # Import AES class from aes.py submodule

# Define the test class for comparing C and Python AES implementations
class TestRijndael(unittest.TestCase):
    def setUp(self):
        # Initialize setup for all test methods
        # Get the project root directory (parent of unit_tests)
        self.project_root = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        # Construct path to rijndael.dll
        dll_path = os.path.join(self.project_root, 'rijndael.dll')
        
        # Load the rijndael.dll library
        try:
            self.lib = ctypes.cdll.LoadLibrary(dll_path)
        except Exception as e:
            # Fail the test if the DLL cannot be loaded
            self.fail(f"Failed to load rijndael.dll: {e}")

        # Define the argument and return types for aes_encrypt_block
        # Takes two 16-byte arrays (plaintext, key), returns pointer to unsigned char
        self.lib.aes_encrypt_block.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte * 16),
            ctypes.POINTER(ctypes.c_ubyte * 16)
        ]
        self.lib.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

        # Access the C runtime's free function to clean up malloc'ed memory
        self.c_free = ctypes.cdll.msvcrt.free
        self.c_free.argtypes = [ctypes.c_void_p]
        self.c_free.restype = None

    def test_encrypt_block(self):
        # Test encryption with a fixed key and plaintext to ensure basic functionality
        # Fixed 16-byte key for AES-128
        key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
        # Fixed 16-byte plaintext
        plaintext = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                          0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        
        # Python implementation: encrypt using aes.py
        aes = AES(key)  # Initialize AES with the key
        py_result = aes.encrypt_block(plaintext)  # Get Python ciphertext
        
        # C implementation: encrypt using rijndael.dll
        c_plaintext = (ctypes.c_ubyte * 16)(*plaintext)  # Convert plaintext to C array
        c_key = (ctypes.c_ubyte * 16)(*key)  # Convert key to C array
        c_result_ptr = self.lib.aes_encrypt_block(c_plaintext, c_key)  # Call C function
        if not c_result_ptr:
            # Fail if the C function returns NULL (e.g., malloc failure)
            self.fail("aes_encrypt_block returned NULL")
        # Convert C result pointer to Python bytes
        c_result = bytes(ctypes.cast(c_result_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)
        
        # Free the memory allocated by aes_encrypt_block
        self.c_free(c_result_ptr)
        
        # Verify that Python and C outputs match
        self.assertEqual(py_result, c_result, "encrypt_block mismatch for fixed input")

    def test_encrypt_block_random_1(self):
        # Test encryption with first random key/plaintext pair
        key = os.urandom(16)  # Secure random key for AES-128
        plaintext = os.urandom(16)  # Secure random plaintext block
        
        # Print the key, plaintext, and outputs in hex for verification
        print(f"Random input 1 key: {key.hex()}")
        print(f"Random input 1 plaintext: {plaintext.hex()}")
        
        # Python implementation: encrypt using aes.py
        aes = AES(key)  # Initialize AES with random key
        py_result = aes.encrypt_block(plaintext)  # Get Python ciphertext
        print(f"Random input 1 Python output: {py_result.hex()}")
        
        # C implementation: encrypt using rijndael.dll
        c_plaintext = (ctypes.c_ubyte * 16)(*plaintext)  # Convert to C array
        c_key = (ctypes.c_ubyte * 16)(*key)  # Convert to C array
        c_result_ptr = self.lib.aes_encrypt_block(c_plaintext, c_key)  # Call C function
        if not c_result_ptr:
            # Fail if C function returns NULL
            self.fail("aes_encrypt_block returned NULL for random input 1")
        # Convert C result to Python bytes
        c_result = bytes(ctypes.cast(c_result_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)
        print(f"Random input 1 C output: {c_result.hex()}")
        
        # Free the allocated memory
        self.c_free(c_result_ptr)
        
        # Verify that Python and C outputs match
        self.assertEqual(py_result, c_result, "encrypt_block mismatch for random input 1")

    def test_encrypt_block_random_2(self):
        # Test encryption with second random key/plaintext pair
        key = os.urandom(16)  # Secure random key for AES-128
        plaintext = os.urandom(16)  # Secure random plaintext block
        
        # Print the key, plaintext, and outputs in hex for verification
        print(f"Random input 2 key: {key.hex()}")
        print(f"Random input 2 plaintext: {plaintext.hex()}")
        
        # Python implementation: encrypt using aes.py
        aes = AES(key)  # Initialize AES with random key
        py_result = aes.encrypt_block(plaintext)  # Get Python ciphertext
        print(f"Random input 2 Python output: {py_result.hex()}")
        
        # C implementation: encrypt using rijndael.dll
        c_plaintext = (ctypes.c_ubyte * 16)(*plaintext)  # Convert to C array
        c_key = (ctypes.c_ubyte * 16)(*key)  # Convert to C array
        c_result_ptr = self.lib.aes_encrypt_block(c_plaintext, c_key)  # Call C function
        if not c_result_ptr:
            # Fail if C function returns NULL
            self.fail("aes_encrypt_block returned NULL for random input 2")
        # Convert C result to Python bytes
        c_result = bytes(ctypes.cast(c_result_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)
        print(f"Random input 2 C output: {c_result.hex()}")
        
        # Free the allocated memory
        self.c_free(c_result_ptr)
        
        # Verify that Python and C outputs match
        self.assertEqual(py_result, c_result, "encrypt_block mismatch for random input 2")

    def test_encrypt_block_random_3(self):
        # Test encryption with third random key/plaintext pair
        key = os.urandom(16)  # Secure random key for AES-128
        plaintext = os.urandom(16)  # Secure random plaintext block
        
        # Print the key, plaintext, and outputs in hex for verification
        print(f"Random input 3 key: {key.hex()}")
        print(f"Random input 3 plaintext: {plaintext.hex()}")
        
        # Python implementation: encrypt using aes.py
        aes = AES(key)  # Initialize AES with random key
        py_result = aes.encrypt_block(plaintext)  # Get Python ciphertext
        print(f"Random input 3 Python output: {py_result.hex()}")
        
        # C implementation: encrypt using rijndael.dll
        c_plaintext = (ctypes.c_ubyte * 16)(*plaintext)  # Convert to C array
        c_key = (ctypes.c_ubyte * 16)(*key)  # Convert to C array
        c_result_ptr = self.lib.aes_encrypt_block(c_plaintext, c_key)  # Call C function
        if not c_result_ptr:
            # Fail if C function returns NULL
            self.fail("aes_encrypt_block returned NULL for random input 3")
        # Convert C result to Python bytes
        c_result = bytes(ctypes.cast(c_result_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)
        print(f"Random input 3 C output: {c_result.hex()}")
        
        # Free the allocated memory
        self.c_free(c_result_ptr)
        
        # Verify that Python and C outputs match
        self.assertEqual(py_result, c_result, "encrypt_block mismatch for random input 3")

if __name__ == '__main__':
    # Ensure the aes submodule is accessible
    project_root = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    sys.path.insert(0, os.path.join(project_root, 'aes'))  # Add aes/ to Python path
    unittest.main()  # Run all tests
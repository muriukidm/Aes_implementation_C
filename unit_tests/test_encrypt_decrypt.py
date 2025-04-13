# Import required modules for unit testing, C library interaction, and path handling
import unittest  # Framework for writing and running unit tests
import ctypes  # For interfacing with rijndael.dll (C implementation)
import os  # For path manipulation and random byte generation
import sys  # For modifying Python's module search path

# Ensure the aes submodule is accessible
project_root = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
aes_path = os.path.join(project_root, 'aes')
if not os.path.exists(aes_path):
    raise ImportError(f"AES submodule directory not found at {aes_path}")
if not os.path.exists(os.path.join(aes_path, 'aes.py')):
    raise ImportError(f"aes.py not found in {aes_path}")
sys.path.insert(0, aes_path)  # Add aes/ to Python path

try:
    from aes import AES  # Import AES class from aes.py in submodule
except ImportError as e:
    raise ImportError(f"Failed to import AES from aes: {e}")

# Define the test class for comparing C and Python AES encryption and decryption
class TestEncryptDecrypt(unittest.TestCase):
    def setUp(self):
        # Initialize setup for all test methods
        # Construct path to rijndael.dll
        dll_path = os.path.join(project_root, 'rijndael.dll')
        
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

        # Define the argument and return types for aes_decrypt_block
        # Takes two 16-byte arrays (ciphertext, key), returns pointer to unsigned char
        self.lib.aes_decrypt_block.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte * 16),
            ctypes.POINTER(ctypes.c_ubyte * 16)
        ]
        self.lib.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

        # Access the C runtime's free function to clean up malloc'ed memory
        self.c_free = ctypes.cdll.msvcrt.free
        self.c_free.argtypes = [ctypes.c_void_p]
        self.c_free.restype = None

    def test_encrypt_decrypt_cycle(self):
        # Test the full encryption and decryption cycle with three random key/plaintext pairs
        for i in range(3):
            # Generate random 16-byte key and plaintext
            key = os.urandom(16)
            plaintext = os.urandom(16)
            
            # Print the key and plaintext in hex for verification
            print(f"Cycle {i+1} key: {key.hex()}")
            print(f"Cycle {i+1} plaintext: {plaintext.hex()}")
            
            # Python implementation: encrypt using aes.py
            aes = AES(key)
            py_ciphertext = aes.encrypt_block(plaintext)
            print(f"Cycle {i+1} Python ciphertext: {py_ciphertext.hex()}")
            
            # C implementation: encrypt using rijndael.dll
            c_plaintext = (ctypes.c_ubyte * 16)(*plaintext)
            c_key = (ctypes.c_ubyte * 16)(*key)
            c_ciphertext_ptr = self.lib.aes_encrypt_block(c_plaintext, c_key)
            if not c_ciphertext_ptr:
                self.fail(f"aes_encrypt_block returned NULL for cycle {i+1}")
            c_ciphertext = bytes(ctypes.cast(c_ciphertext_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)
            print(f"Cycle {i+1} C ciphertext: {c_ciphertext.hex()}")
            
            # Free the memory allocated by aes_encrypt_block
            self.c_free(c_ciphertext_ptr)
            
            # Verify that Python and C ciphertexts match
            self.assertEqual(py_ciphertext, c_ciphertext, f"Encryption mismatch for cycle {i+1}")

            # Python implementation: decrypt using aes.py
            py_decrypted = aes.decrypt_block(py_ciphertext)
            print(f"Cycle {i+1} Python decrypted: {py_decrypted.hex()}")
            
            # C implementation: decrypt using rijndael.dll
            c_ciphertext_array = (ctypes.c_ubyte * 16)(*py_ciphertext)
            c_decrypted_ptr = self.lib.aes_decrypt_block(c_ciphertext_array, c_key)
            if not c_decrypted_ptr:
                self.fail(f"aes_decrypt_block returned NULL for cycle {i+1}")
            c_decrypted = bytes(ctypes.cast(c_decrypted_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)
            print(f"Cycle {i+1} C decrypted: {c_decrypted.hex()}")
            
            # Free the memory allocated by aes_decrypt_block
            self.c_free(c_decrypted_ptr)
            
            # Verify that decrypted outputs match the original plaintext
            self.assertEqual(py_decrypted, plaintext, f"Python decryption mismatch for cycle {i+1}")
            self.assertEqual(c_decrypted, plaintext, f"C decryption mismatch for cycle {i+1}")
            self.assertEqual(py_decrypted, c_decrypted, f"Decrypted outputs differ for cycle {i+1}")

if __name__ == '__main__':
    unittest.main()  # Run all tests
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

# Define the test class for comparing C and Python AES implementations
class TestRijndael(unittest.TestCase):
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

        # Access the C runtime's free function to clean up malloc'ed memory
        self.c_free = ctypes.cdll.msvcrt.free
        self.c_free.argtypes = [ctypes.c_void_p]
        self.c_free.restype = None

    def test_encrypt_block(self):
        # Test encryption with a fixed key and plaintext to ensure basic functionality
        key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
        plaintext = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                          0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        
        # Python implementation: encrypt using aes.py
        aes = AES(key)
        py_result = aes.encrypt_block(plaintext)
        
        # C implementation: encrypt using rijndael.dll
        c_plaintext = (ctypes.c_ubyte * 16)(*plaintext)
        c_key = (ctypes.c_ubyte * 16)(*key)
        c_result_ptr = self.lib.aes_encrypt_block(c_plaintext, c_key)
        if not c_result_ptr:
            self.fail("aes_encrypt_block returned NULL")
        c_result = bytes(ctypes.cast(c_result_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)
        
        # Free the memory allocated by aes_encrypt_block
        self.c_free(c_result_ptr)
        
        # Verify that Python and C outputs match
        self.assertEqual(py_result, c_result, "encrypt_block mismatch for fixed input")

    def test_encrypt_block_random(self):
        # Test encryption with three random key/plaintext pairs to verify consistency
        for i in range(3):
            key = os.urandom(16)
            plaintext = os.urandom(16)
            
            print(f"Random input {i+1} key: {key.hex()}")
            print(f"Random input {i+1} plaintext: {plaintext.hex()}")
            
            # Python implementation: encrypt using aes.py
            aes = AES(key)
            py_result = aes.encrypt_block(plaintext)
            print(f"Random input {i+1} Python output: {py_result.hex()}")
            
            # C implementation: encrypt using rijndael.dll
            c_plaintext = (ctypes.c_ubyte * 16)(*plaintext)
            c_key = (ctypes.c_ubyte * 16)(*key)
            c_result_ptr = self.lib.aes_encrypt_block(c_plaintext, c_key)
            if not c_result_ptr:
                self.fail(f"aes_encrypt_block returned NULL for random input {i+1}")
            c_result = bytes(ctypes.cast(c_result_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)
            print(f"Random input {i+1} C output: {c_result.hex()}")
            
            # Free the allocated memory
            self.c_free(c_result_ptr)
            
            # Verify that Python and C outputs match for this random input
            self.assertEqual(py_result, c_result, f"encrypt_block mismatch for random input {i+1}")

if __name__ == '__main__':
    unittest.main()  # Run all tests
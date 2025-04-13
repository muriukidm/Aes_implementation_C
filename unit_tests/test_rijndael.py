import unittest
import ctypes
import os
import sys
from aes.aes import AES

class TestRijndael(unittest.TestCase):
    def setUp(self):
        # Set up paths
        self.project_root = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
        dll_path = os.path.join(self.project_root, 'rijndael.dll')
        
        # Load rijndael.dll
        try:
            self.lib = ctypes.cdll.LoadLibrary(dll_path)
        except Exception as e:
            self.fail(f"Failed to load rijndael.dll: {e}")

        # Define aes_encrypt_block function signature
        self.lib.aes_encrypt_block.argtypes = [
            ctypes.POINTER(ctypes.c_ubyte * 16),
            ctypes.POINTER(ctypes.c_ubyte * 16)
        ]
        self.lib.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte)

        # Access C runtime free function for memory cleanup
        self.c_free = ctypes.cdll.msvcrt.free
        self.c_free.argtypes = [ctypes.c_void_p]
        self.c_free.restype = None

    def test_encrypt_block(self):
        # Test key and plaintext
        key = bytes([0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f])
        plaintext = bytes([0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                          0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        
        # Python aes.py encrypt_block
        aes = AES(key)
        py_result = aes.encrypt_block(plaintext)
        
        # C rijndael.dll aes_encrypt_block
        c_plaintext = (ctypes.c_ubyte * 16)(*plaintext)
        c_key = (ctypes.c_ubyte * 16)(*key)
        c_result_ptr = self.lib.aes_encrypt_block(c_plaintext, c_key)
        if not c_result_ptr:
            self.fail("aes_encrypt_block returned NULL")
        c_result = bytes(ctypes.cast(c_result_ptr, ctypes.POINTER(ctypes.c_ubyte * 16)).contents)
        
        # Free the allocated memory
        self.c_free(c_result_ptr)
        
        # Compare
        self.assertEqual(py_result, c_result, "encrypt_block mismatch between rijndael.dll and aes.py")

if __name__ == '__main__':
    # Ensure aes submodule is in sys.path
    project_root = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    sys.path.insert(0, os.path.join(project_root, 'aes'))
    unittest.main()
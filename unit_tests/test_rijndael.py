import ctypes
import os
import random
import sys

# Debug: Print key paths
print("Current working directory:", os.getcwd())
print("Test script location:", os.path.abspath(__file__))

# Calculate project root and submodule path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))  # rijndael starter code
submodule_path = os.path.join(project_root, 'aes')
print("Project root:", project_root)
print("Submodule path:", submodule_path)
print("Submodule exists:", os.path.exists(submodule_path))
if os.path.exists(project_root):
    print("Project root contents:", os.listdir(project_root))

if not os.path.exists(submodule_path):
    print(f"Error: Submodule path {submodule_path} does not exist")
    sys.exit(1)

# Add submodule to sys.path
sys.path.append(submodule_path)
print("Updated sys.path:", sys.path)

try:
    from aes import AES  # From submodule aes
except ModuleNotFoundError as e:
    print(f"Error: Failed to import AES from aes. Ensure aes.py exists in {submodule_path}")
    if os.path.exists(submodule_path):
        print("Submodule contents:", os.listdir(submodule_path))
    raise e

# Load C library
lib_path = os.path.join(project_root, 'rijndael.so')
if os.name == 'nt':
    lib_path = lib_path.replace('.so', '.dll')  # Windows may use .dll
print("Library path:", lib_path)
try:
    rijndael = ctypes.CDLL(lib_path)
except OSError as e:
    print(f"Error: Could not load {lib_path}. Ensure 'make' was run. Error: {e}")
    sys.exit(1)

# Configure C function signatures
rijndael.sub_bytes.argtypes = [ctypes.POINTER(ctypes.c_ubyte * 16)]
rijndael.aes_encrypt_block.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte * 16),
    ctypes.POINTER(ctypes.c_ubyte * 16)
]
rijndael.aes_encrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte * 16)
rijndael.aes_decrypt_block.argtypes = [
    ctypes.POINTER(ctypes.c_ubyte * 16),
    ctypes.POINTER(ctypes.c_ubyte * 16)
]
rijndael.aes_decrypt_block.restype = ctypes.POINTER(ctypes.c_ubyte * 16)

def to_c_buffer(data):
    """Convert Python bytes to C-compatible buffer."""
    if len(data) != 16:
        raise ValueError("Data must be 16 bytes")
    return (ctypes.c_ubyte * 16)(*data)

def from_c_buffer(c_buffer):
    """Convert C buffer to Python bytes."""
    return bytes(c_buffer.contents)

def test_sub_bytes():
    """Test sub_bytes against boppreh/aes."""
    for _ in range(3):
        block = bytes(random.randint(0, 255) for _ in range(16))
        c_block = to_c_buffer(block)
        rijndael.sub_bytes(c_block)
        c_result = bytes(c_block)
        py_block = bytearray(block)
        AES.sub_bytes(py_block)
        assert c_result == bytes(py_block), f"sub_bytes mismatch: {c_result} != {py_block}"

def test_encrypt_block():
    """Test aes_encrypt_block against boppreh/aes."""
    plaintext = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
    key = bytes([50, 20, 46, 86, 67, 9, 70, 27, 75, 17, 51, 17, 4, 8, 6, 99])
    expected_ct = bytes([75, 149, 134, 147, 180, 233, 196, 235, 146, 179, 232, 105, 175, 64, 224, 206])
    
    c_pt = to_c_buffer(plaintext)
    c_key = to_c_buffer(key)
    c_ct_ptr = rijndael.aes_encrypt_block(c_pt, c_key)
    c_ct = from_c_buffer(c_ct_ptr)
    py_ct = AES(key).encrypt_block(plaintext)
    
    assert c_ct == expected_ct, f"C encrypt fixed mismatch: {c_ct} != {expected_ct}"
    assert c_ct == py_ct, f"C vs Python encrypt mismatch: {c_ct} != {py_ct}"
    
    for _ in range(3):
        pt = bytes(random.randint(0, 255) for _ in range(16))
        key = bytes(random.randint(0, 255) for _ in range(16))
        c_pt = to_c_buffer(pt)
        c_key = to_c_buffer(key)
        c_ct_ptr = rijndael.aes_encrypt_block(c_pt, c_key)
        c_ct = from_c_buffer(c_ct_ptr)
        py_ct = AES(key).encrypt_block(pt)
        assert c_ct == py_ct, f"Random encrypt mismatch: {c_ct} != {py_ct}"

def test_decrypt_block():
    """Test aes_decrypt_block against boppreh/aes."""
    ciphertext = bytes([75, 149, 134, 147, 180, 233, 196, 235, 146, 179, 232, 105, 175, 64, 224, 206])
    key = bytes([50, 20, 46, 86, 67, 9, 70, 27, 75, 17, 51, 17, 4, 8, 6, 99])
    expected_pt = bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16])
    
    c_ct = to_c_buffer(ciphertext)
    c_key = to_c_buffer(key)
    c_pt_ptr = rijndael.aes_decrypt_block(c_ct, c_key)
    c_pt = from_c_buffer(c_pt_ptr)
    py_pt = AES(key).decrypt_block(ciphertext)
    
    assert c_pt == expected_pt, f"C decrypt fixed mismatch: {c_pt} != {expected_pt}"
    assert c_pt == py_pt, f"C vs Python decrypt mismatch: {c_pt} != {py_pt}"
    
    for _ in range(3):
        ct = bytes(random.randint(0, 255) for _ in range(16))
        key = bytes(random.randint(0, 255) for _ in range(16))
        c_ct = to_c_buffer(ct)
        c_key = to_c_buffer(key)
        c_pt_ptr = rijndael.aes_decrypt_block(c_ct, c_key)
        c_pt = from_c_buffer(c_pt_ptr)
        py_pt = AES(key).decrypt_block(ct)
        assert c_pt == py_pt, f"Random decrypt mismatch: {c_pt} != {py_pt}"

def test_round_trip():
    """Test encrypt followed by decrypt recovers plaintext."""
    for _ in range(3):
        pt = bytes(random.randint(0, 255) for _ in range(16))
        key = bytes(random.randint(0, 255) for _ in range(16))
        c_pt = to_c_buffer(pt)
        c_key = to_c_buffer(key)
        c_ct_ptr = rijndael.aes_encrypt_block(c_pt, c_key)
        c_ct = to_c_buffer(from_c_buffer(c_ct_ptr))
        c_recovered_ptr = rijndael.aes_decrypt_block(c_ct, c_key)
        c_recovered = from_c_buffer(c_recovered_ptr)
        assert c_recovered == pt, f"Round-trip mismatch: {c_recovered} != {pt}"

if __name__ == "__main__":
    print("Running tests...")
    test_sub_bytes()
    test_encrypt_block()
    test_decrypt_block()
    test_round_trip()
    print("All tests passed!")
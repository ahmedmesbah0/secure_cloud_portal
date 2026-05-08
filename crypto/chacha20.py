"""
ChaCha20 Stream Cipher - Implemented from scratch.

ChaCha20 is a stream cipher designed by Daniel J. Bernstein.
- Key size: 256 bits (32 bytes)
- Nonce size: 96 bits (12 bytes)  
- Block size: 512 bits (64 bytes) of keystream per block
- Uses ARX operations: Add, Rotate, XOR (no S-boxes needed)

How it works:
1. Build a 4x4 matrix of 32-bit words from constants + key + counter + nonce
2. Apply 20 rounds (10 column rounds + 10 diagonal rounds)
3. Add the original matrix to the result
4. Output 64 bytes of keystream
5. XOR keystream with plaintext to encrypt (same operation decrypts)
"""

from .utils import rotate_left_32


class ChaCha20:
    """
    ChaCha20 stream cipher.
    
    Usage:
        cipher = ChaCha20(key=32_byte_key, nonce=12_byte_nonce)
        ciphertext = cipher.encrypt(plaintext)
        # Decryption is the same operation:
        plaintext = ChaCha20(key, nonce).encrypt(ciphertext)
    """
    
    # "expand 32-byte k" in ASCII - the ChaCha20 constants
    CONSTANTS = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    
    def __init__(self, key: bytes, nonce: bytes):
        """
        Initialize ChaCha20 with a 32-byte key and 12-byte nonce.
        
        The 4x4 state matrix layout (each cell is 32 bits):
        ┌──────────┬──────────┬──────────┬──────────┐
        │ const[0] │ const[1] │ const[2] │ const[3] │
        ├──────────┼──────────┼──────────┼──────────┤
        │ key[0]   │ key[1]   │ key[2]   │ key[3]   │
        ├──────────┼──────────┼──────────┼──────────┤
        │ key[4]   │ key[5]   │ key[6]   │ key[7]   │
        ├──────────┼──────────┼──────────┼──────────┤
        │ counter  │ nonce[0] │ nonce[1] │ nonce[2] │
        └──────────┴──────────┴──────────┴──────────┘
        """
        if len(key) != 32:
            raise ValueError("Key must be 32 bytes (256 bits)")
        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes (96 bits)")
        
        self.key = key
        self.nonce = nonce
    
    @staticmethod
    def _to_u32(data: bytes, offset: int) -> int:
        """Read a little-endian 32-bit integer from bytes."""
        return (data[offset] | (data[offset+1] << 8) |
                (data[offset+2] << 16) | (data[offset+3] << 24))
    
    @staticmethod
    def _from_u32(value: int) -> bytes:
        """Convert a 32-bit integer to little-endian bytes."""
        return bytes([
            value & 0xFF, (value >> 8) & 0xFF,
            (value >> 16) & 0xFF, (value >> 24) & 0xFF
        ])
    
    @staticmethod
    def _quarter_round(state: list, a: int, b: int, c: int, d: int):
        """
        ChaCha20 quarter round - the core mixing operation.
        
        Performs 4 ARX (Add-Rotate-XOR) steps:
        1. a += b; d ^= a; d <<<= 16
        2. c += d; b ^= c; b <<<= 12
        3. a += b; d ^= a; d <<<= 8
        4. c += d; b ^= c; b <<<= 7
        """
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = rotate_left_32(state[d], 16)
        
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = rotate_left_32(state[b], 12)
        
        state[a] = (state[a] + state[b]) & 0xFFFFFFFF
        state[d] ^= state[a]
        state[d] = rotate_left_32(state[d], 8)
        
        state[c] = (state[c] + state[d]) & 0xFFFFFFFF
        state[b] ^= state[c]
        state[b] = rotate_left_32(state[b], 7)
    
    def _chacha_block(self, counter: int) -> bytes:
        """
        Generate one 64-byte keystream block.
        
        Steps:
        1. Initialize state matrix with constants, key, counter, nonce
        2. Copy state as 'initial_state'
        3. Apply 20 rounds (10 double-rounds of column + diagonal)
        4. Add initial_state to final state (mod 2^32)
        5. Serialize to 64 bytes
        """
        # Build initial state
        state = list(self.CONSTANTS)  # Words 0-3: constants
        
        # Words 4-11: key (8 x 32-bit words from 32 bytes)
        for i in range(8):
            state.append(self._to_u32(self.key, i * 4))
        
        # Word 12: counter
        state.append(counter & 0xFFFFFFFF)
        
        # Words 13-15: nonce (3 x 32-bit words from 12 bytes)
        for i in range(3):
            state.append(self._to_u32(self.nonce, i * 4))
        
        # Save initial state for final addition
        initial = list(state)
        
        # 20 rounds = 10 double-rounds
        for _ in range(10):
            # Column rounds
            self._quarter_round(state, 0, 4,  8, 12)
            self._quarter_round(state, 1, 5,  9, 13)
            self._quarter_round(state, 2, 6, 10, 14)
            self._quarter_round(state, 3, 7, 11, 15)
            # Diagonal rounds
            self._quarter_round(state, 0, 5, 10, 15)
            self._quarter_round(state, 1, 6, 11, 12)
            self._quarter_round(state, 2, 7,  8, 13)
            self._quarter_round(state, 3, 4,  9, 14)
        
        # Add initial state to working state
        output = b''
        for i in range(16):
            state[i] = (state[i] + initial[i]) & 0xFFFFFFFF
            output += self._from_u32(state[i])
        
        return output
    
    def encrypt(self, plaintext: bytes) -> bytes:
        """
        Encrypt plaintext by XORing with the keystream.
        
        Generates keystream blocks as needed, incrementing the counter.
        Since XOR is symmetric, this same method also decrypts.
        """
        ciphertext = bytearray()
        counter = 0
        
        for offset in range(0, len(plaintext), 64):
            keystream = self._chacha_block(counter)
            chunk = plaintext[offset:offset + 64]
            # XOR each byte with the keystream
            for i in range(len(chunk)):
                ciphertext.append(chunk[i] ^ keystream[i])
            counter += 1
        
        return bytes(ciphertext)
    
    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext. Same as encrypt since XOR is symmetric."""
        return self.encrypt(ciphertext)

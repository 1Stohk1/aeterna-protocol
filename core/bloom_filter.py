"""
AETERNA Protocol — Bloom Filter
A lightweight, dependency-free probabilistic data structure designed to represent
a set of message hashes in a constant space, preventing packet fragmentation.
"""

import base64
import hashlib

class BloomFilter:
    """
    A probabilistic data structure to represent message hashes.
    """
    def __init__(self, size_bits: int = 512, num_hashes: int = 7):
        if size_bits % 8 != 0:
            raise ValueError("size_bits must be a multiple of 8")
        self.size_bits = size_bits
        self.num_hashes = num_hashes
        self.bitarray = bytearray(size_bits // 8)

    def add(self, item: str):
        """
        Adds an item to the Bloom Filter by setting the corresponding bits to 1.
        """
        for i in range(self.num_hashes):
            h = hashlib.sha256(f"{item}:{i}".encode("utf-8")).digest()
            index = int.from_bytes(h, byteorder="big") % self.size_bits
            byte_index = index // 8
            bit_index = index % 8
            self.bitarray[byte_index] |= (1 << bit_index)

    def __contains__(self, item: str) -> bool:
        """
        Returns True if the item is probably in the filter, False if it is definitely not.
        """
        for i in range(self.num_hashes):
            h = hashlib.sha256(f"{item}:{i}".encode("utf-8")).digest()
            index = int.from_bytes(h, byteorder="big") % self.size_bits
            byte_index = index // 8
            bit_index = index % 8
            if not (self.bitarray[byte_index] & (1 << bit_index)):
                return False
        return True

    def to_base64(self) -> str:
        """
        Serializes the bitarray to a base64 string.
        """
        return base64.b64encode(self.bitarray).decode("utf-8")

    @classmethod
    def from_base64(cls, b64_str: str, size_bits: int = 512, num_hashes: int = 7) -> 'BloomFilter':
        """
        Restores a BloomFilter from a base64 string.
        """
        decoded = base64.b64decode(b64_str.encode("utf-8"))
        if len(decoded) != size_bits // 8:
            raise ValueError("Decoded byte length mismatch with size_bits configuration")
        bf = cls(size_bits=size_bits, num_hashes=num_hashes)
        bf.bitarray = bytearray(decoded)
        return bf

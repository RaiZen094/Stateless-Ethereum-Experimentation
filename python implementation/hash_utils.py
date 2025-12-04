# hash_utils.py
"""
Utilities for hashing.

Two types of hashing:
1. OFF-CIRCUIT (merkle_tree.py): Plain Python SHA-256 for tree building
2. IN-CIRCUIT (zk_merkle.py): Poseidon via poseidon_hash from PySNARK library

This separation is crucial:
- Off-circuit: Build tree, extract opening (no SNARK recording)
- In-circuit: Prove membership using Poseidon constraints (SNARK recording)
"""

import hashlib

# BN254 field modulus (used by PySNARK and most backends)
FIELD_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617


def sha256_to_field(*values: int) -> int:
    """
    Hash integers using SHA-256 and map into field (OFF-CIRCUIT).

    Used for building trees, NOT for proving membership.
    Deterministic: same inputs always produce same output across runs.
    
    Args:
        *values: integers representing field elements
    
    Returns:
        integer in [0, FIELD_MODULUS)
    """
    h = hashlib.sha256()
    for v in values:
        # Fixed-width (32 bytes) encoding ensures deterministic hashing
        h.update(v.to_bytes(32, byteorder="big", signed=False))
    digest = h.digest()
    as_int = int.from_bytes(digest, byteorder="big")
    return as_int % FIELD_MODULUS


def merkle_hash2(left: int, right: int) -> int:
    """
    Merkle parent hash for arity=2 (OFF-CIRCUIT).

    IMPORTANT: This is for OFF-CIRCUIT tree building ONLY.
    
    Usage:
    - merkle_tree.py: Building tree, computing opening
    - NOT for proving (that's in-circuit Poseidon)
    
    Design:
    - Uses SHA-256 (deterministic, cryptographically secure)
    - Different from Rust Poseidon but semantically equivalent
    - Reduced to field modulus for compatibility
    
    Args:
        left: left child hash
        right: right child hash
    
    Returns:
        parent hash
    """
    return sha256_to_field(left, right)

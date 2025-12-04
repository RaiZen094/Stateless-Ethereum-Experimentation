# zk_merkle.py
"""
Merkle opening verification as a PySNARK circuit.

This is the ZK part: given a leaf, a Merkle opening (siblings + positions),
we recompute the root INSIDE THE CIRCUIT and enforce that it equals a public root.

Key difference from naive approach:
- Hash computations are NOT external oracles
- All hashes are computed IN-CIRCUIT using Poseidon
- Every hash operation creates ~350-400 constraints
- Prover must prove every hash is computed correctly
- Verifier checks all hash computations were correct

This mirrors the Rust logic:
- opening_gadget(...) in zk.rs (hash constraint generation)
- OpeningCircuit::circuit(...) in circuit.rs (root enforcement)

PySNARK Integration:
- Uses poseidon_hash from PySNARK library
- All operations on LinComb objects create constraints
- Constraints are recorded by @snark decorator in runtime
"""

from typing import List
from pysnark.runtime import PrivVal, PubVal, LinComb

# Import Poseidon hash gadget from PySNARK library
# This implements in-circuit Poseidon hashing with ~350-400 constraints per hash
# When called with LinComb inputs, each operation creates a constraint automatically
try:
    from poseidon_hash import poseidon_hash as poseidon_circuit_hash
except ImportError:
    try:
        # Alternative import path
        from pysnark.poseidon_hash import poseidon_hash as poseidon_circuit_hash
    except ImportError:
        raise ImportError(
            "poseidon_hash not found in PySNARK library. "
            "Install PySNARK with Poseidon support: pip install pysnark[zkinterface] "
            "and set backend: export PYSNARK_BACKEND=zkinterface"
        )


def merkle_opening_circuit(
    leaf: LinComb,
    siblings: List[LinComb],
    positions: List[int],
    public_root: LinComb,
) -> None:
    """
    Merkle membership circuit - IN-CIRCUIT POSEIDON VERSION.

    Inputs:
    - leaf: LinComb (PrivVal)        (leaf hash, private witness)
    - siblings: List[LinComb] (PrivVal) (Merkle siblings for each level, private witnesses)
    - positions: List[int]           (0 or 1, public knowledge: which child at each level)
    - public_root: LinComb (PubVal)  (expected root, public input)

    Circuit Logic (IN-CIRCUIT):
    ========================
    1. needle = leaf (start from bottom of tree)
    2. For each level h (bottom-up)
        a) Get position[h] and sibling[h]
        b) Route based on position:
           - If pos == 0: left=needle, right=sibling (we're LEFT child)
           - If pos == 1: left=sibling, right=needle (we're RIGHT child)
        c) Compute: needle = Poseidon(left, right)
           ↓ This creates ~350-400 constraints in the SNARK!
    3. After all levels: needle contains computed root
    4. Assert: (needle - public_root).assert_zero()
       ↓ This creates 1 constraint enforcing equality

    Proof Semantics:
    ===============
    What the prover proves:
    - "I know a leaf and siblings such that
       when hashed in the specified order,
       I obtain this public root."

    What the verifier checks:
    - "All Poseidon hash computations are correct"
    - "All position routings are correct"
    - "The computed root equals the public root"

    Constraints Generated:
    =====================
    For a tree of height H:
    - H * 350-400 constraints from Poseidon hashes
    - 1 constraint from root equality check
    - Total: ~H*350-400 constraints

    This mirrors the Rust logic:
    - opening_gadget(...) in zk.rs (hash constraint generation)
    - OpeningCircuit::circuit(...) in circuit.rs (root enforcement)

    PySNARK Semantics:
    ==================
    - All operations on LinComb (PrivVal/PubVal) create constraints
    - poseidon_circuit_hash() takes List[LinComb] → List[LinComb]
    - Each arithmetic operation is recorded as constraint
    - Backend (zkinterface/zkifbellman) generates proof
    """

    # Validate input sizes match
    assert len(siblings) == len(positions), (
        f"Length mismatch: {len(siblings)} siblings but {len(positions)} positions"
    )

    # Validate position bits are in valid range (checked by prover, not circuit)
    for h, pos in enumerate(positions):
        assert pos in (0, 1), (
            f"Invalid position at level {h}: {pos}. Must be 0 or 1."
        )

    # Start from leaf and hash upward
    needle = leaf  # needle is LinComb (PrivVal)

    # Walk up tree level by level (bottom-up traversal)
    for h in range(len(positions)):
        position_bit = positions[h]  # Public: 0 or 1
        sibling = siblings[h]         # Private: LinComb (PrivVal)

        # Route inputs based on position bit
        # position_bit determines which child we are
        if position_bit == 0:
            # Current node is LEFT child at this level
            # Hash order: (needle, sibling) = (left, right)
            left = needle
            right = sibling
        else:
            # Current node is RIGHT child at this level
            # Hash order: (sibling, needle) = (left, right)
            left = sibling
            right = needle

        # CRITICAL: Hash computation IN-CIRCUIT
        # ===================================
        # Call poseidon_hash with two LinComb inputs
        # This is NOT an external oracle - it's computed in the circuit
        # Return value is List[LinComb] with output elements
        parent_hash_list = poseidon_circuit_hash([left, right])

        # Extract first output of Poseidon sponge
        # This becomes the parent hash for next level
        needle = parent_hash_list[0]  # needle is now new parent (LinComb)

    # Final Constraint: Root Equality
    # ================================
    # needle now contains computed root (after all levels)
    # Enforce: computed_root == public_root
    # In PySNARK: (needle - public_root).assert_zero()
    # This creates 1 constraint: needle - public_root = 0
    (needle - public_root).assert_zero()

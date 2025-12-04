# main_prove_verify.py
"""
Example driver that ties everything together:

- Generate a random binary Merkle tree.
- Compute an opening for one leaf.
- Run the PySNARK circuit to prove membership (leaf is in tree).
"""

import random
from typing import List

from pysnark.runtime import PrivVal, PubVal, snark
from merkle_tree import MerkleTree, field
from zk_merkle import merkle_opening_circuit


def generate_random_leaves(num_leaves: int) -> List[int]:
    """
    Generate random field elements to act as leaf values.
    """
    return [field(random.getrandbits(128)) for _ in range(num_leaves)]


@snark
def merkle_membership_example():
    """
    Merkle membership proof using in-circuit Poseidon hashing.

    PySNARK Execution Flow:
    =======================
    1. @snark decorator starts recording all operations as constraints
    2. OFF-CIRCUIT operations (outside decorator context):
       - Tree building (uses SHA-256)
       - Opening extraction (just data structure)
    3. IN-CIRCUIT operations (inside merkle_opening_circuit):
       - Poseidon hashing creates ~350-400 constraints per hash
       - Position routing verified at each level
       - Root equality enforced (1 constraint)
    4. @snark decorator stops recording and:
       - Compiles circuit from recorded constraints
       - Generates witness from actual values
       - Creates proof (if proving mode)
       - Verifies proof (if verifying mode)

    Data Flow:
    ==========
    Off-circuit (plain Python):
    ├─ Generate random leaves
    ├─ Build Merkle tree (SHA-256 hashing)
    ├─ Pick random leaf index
    ├─ Compute opening (siblings + positions)
    └─ Convert to PySNARK values

    In-circuit (PySNARK recording):
    ├─ leaf_priv = PrivVal(leaf) → witness variable
    ├─ siblings = [PrivVal(s) for s in opening] → witness variables
    ├─ For each level:
    │  ├─ poseidon_circuit_hash([needle, sibling])
    │  │  └─ Creates ~350-400 constraints
    │  └─ needle = parent_hash → new witness
    ├─ Final: (needle - root_pub).assert_zero()
    │  └─ Creates 1 constraint
    └─ Total: ~350-400*H + 1 constraints

    Proof Semantics:
    ================
    Prover proves: 
    - "I know leaf and siblings such that when hashed via Poseidon in order,
       with position routing, I obtain the public root."
    
    Verifier checks:
    - All Poseidon computations are correct
    - All position routings are correct
    - Final root matches public input
    - Proof is valid (via backend cryptography)

    Constraint Details:
    ===================
    - Tree height = 4 → 16 leaves (NUM_LEAVES)
    - Proving 1 leaf per example
    - Circuit size:
        * Poseidon per hash: ~350-400 constraints
        * Hash operations per proof: H = 4
        * Total: ~4 * 350-400 + 1 ≈ 1400-1600 constraints
    
    This mirrors the Rust logic:
    - opening_gadget in zk.rs (in-circuit hash)
    - OpeningCircuit::circuit in circuit.rs (root constraint)
    """

    NUM_LEAVES = 16  # similar to NUM_KEYS in Rust benchmark
    leaves = generate_random_leaves(NUM_LEAVES)

    # ============================================================
    # OFF-CIRCUIT: Build tree, extract opening (no SNARK recording)
    # ============================================================
    
    # 1. Build Merkle tree (uses SHA-256, not in circuit)
    tree = MerkleTree(leaves)
    root_int = tree.root()

    # 2. Pick a random leaf index (off-circuit)
    index = random.randrange(NUM_LEAVES)
    leaf_int = leaves[index]

    # 3. Compute opening: siblings and positions (off-circuit)
    siblings_int, positions = tree.opening(index)

    # ============================================================
    # IN-CIRCUIT: Convert to PySNARK values (within @snark context)
    # ============================================================
    
    # 4. Convert to PySNARK field values
    #    - PrivVal: private witnesses (created as variables)
    #    - PubVal: public inputs (verifier knows these)
    leaf_priv = PrivVal(leaf_int)
    siblings_priv = [PrivVal(s) for s in siblings_int]
    root_pub = PubVal(root_int)

    # ============================================================
    # IN-CIRCUIT: Run Merkle membership proof with Poseidon
    # ============================================================
    
    # 5. Call merkle_opening_circuit (all constraints recorded here)
    #    - Poseidon hashing: IN-CIRCUIT (~350-400 constraints per hash)
    #    - Position routing: IN-CIRCUIT (verified at each level)
    #    - Root constraint: IN-CIRCUIT (1 constraint)
    merkle_opening_circuit(leaf_priv, siblings_priv, positions, root_pub)

    # If we reach here without assertion failing:
    # ✓ PySNARK has verified all in-circuit constraints
    # ✓ All Poseidon hashes computed correctly
    # ✓ Position routing verified
    # ✓ Computed root matches public root
    # ✓ Proof generated (if proving mode)


if __name__ == "__main__":
    # When you run this file with PySNARK configured, the @snark decorator
    # will cause PySNARK to:
    # - record the circuit defined by merkle_membership_example(),
    # - perform proving / verification depending on backend.
    merkle_membership_example()

# merkle_tree.py
"""
Binary Merkle tree using field elements and our merkle_hash2 function.

This is the "off-chain" / non-ZK part: we build the tree and compute Merkle openings
in plain Python, exactly like the Rust helper does.
"""

from typing import List, Tuple
from hash_utils import merkle_hash2, FIELD_MODULUS


def field(val: int) -> int:
    """
    Convert a Python int to a field element by reducing modulo FIELD_MODULUS.
    This is analogous to BlsScalar::from(...) in Rust.
    """
    return val % FIELD_MODULUS


class MerkleTree:
    """
    Binary Merkle tree (arity = 2).

    - leaves: list of field elements (ints mod FIELD_MODULUS)
    - levels[0] = leaves
    - levels[1] = parents of leaves
    - ...
    - levels[-1][0] = root
    """

    def __init__(self, leaves: List[int]) -> None:
        if len(leaves) == 0:
            raise ValueError("Tree must have at least one leaf")
        # Normalize all leaves to field elements
        self.leaves = [field(x) for x in leaves]
        self.levels: List[List[int]] = []
        self._build_tree()

    def _build_tree(self) -> None:
        """
        Build the full tree bottom-up.

        For odd number of nodes, duplicate the last node (like typical Merkle).
        """
        level = self.leaves[:]
        self.levels.append(level)

        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                left = level[i]
                if i + 1 < len(level):
                    right = level[i + 1]
                else:
                    # if odd, duplicate last
                    right = left
                parent = merkle_hash2(left, right)
                next_level.append(parent)
            self.levels.append(next_level)
            level = next_level

    def root(self) -> int:
        """
        Return the root hash of the tree (a field element).
        """
        return self.levels[-1][0]

    def opening(self, index: int) -> Tuple[List[int], List[int]]:
        """
        Compute the Merkle opening (siblings, positions) for a given leaf index.

        Returns: (siblings, positions)
        - siblings[h] = sibling hash at height h (0 = leaf level, up to H-1)
        - positions[h] = 0 if our node was LEFT child at that level,
                         1 if our node was RIGHT child.

        Example for a tree with leaves [A, B, C, D] and opening(0):
        Tree structure:
                    root
                   /    \
                 N1       N2
                /  \     /  \
               A    B   C    D
        
        Opening for A (index=0):
        - positions[0] = 0  (A is LEFT child of N1)
        - siblings[0] = B   (sibling at leaf level)
        - positions[1] = 0  (N1 is LEFT child of root)
        - siblings[1] = N2  (sibling at next level)

        Verification: Recompute root as H(H(A, B), H(C, D)) = H(N1, N2) = root ✓

        This is conceptually equivalent to the Rust `Opening<Item<T>, H, ARITY>`.
        At each level we know: (1) where the path goes (left/right), and (2) what the sibling is.

        PySNARK Usage:
        - These values are passed as PrivVal (leaf, siblings) and public/position info
        - The circuit verifies the opening using merkle_opening_circuit()
        """
        if index < 0 or index >= len(self.leaves):
            raise IndexError("Leaf index out of range")

        siblings: List[int] = []
        positions: List[int] = []

        idx = index
        # We go from leaf level up to just before the root
        for level in range(len(self.levels) - 1):
            layer = self.levels[level]
            # Sibling index: flip the last bit (idx ^ 1)
            # If idx is even (left child), sib is odd (right child), and vice versa
            sib_idx = idx ^ 1
            if sib_idx >= len(layer):
                sib = layer[idx]  # if no sibling (odd), duplicate self
            else:
                sib = layer[sib_idx]

            siblings.append(sib)
            # Position: 0 if even (left child), 1 if odd (right child)
            # Correct formula: extract bit at position 'level'
            positions.append(idx % 2)

            # Move up one level: integer division by 2
            idx //= 2

        return siblings, positions

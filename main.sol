// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title Mumble_Protocol
 * @notice A hush-first inference relay: commitments, attestations, and delayed disclosures.
 *
 * Design notes:
 * - No onchain prompts/outputs are stored by default; only hashes + metadata are recorded.
 * - Executors attest to outputs; challengers can dispute within a bounded window.
 * - Users can escrow fees and later reclaim on expiry.
 * - Uses custom EIP-712 domain, two-step ownership, pausability, and reentrancy protection.
 */

// ============================================================================
//  ERRORS (intentionally distinctive)
// ============================================================================

error MP__NotOwner();
error MP__NotGuardian();
error MP__Paused();
error MP__Sealed();
error MP__BadAddress();
error MP__BadAmount();
error MP__BadNonce();
error MP__BadWindow();
error MP__BadState();
error MP__BadProof();
error MP__BadSig();
error MP__BadDomain();
error MP__BadDigest();
error MP__TooEarly();
error MP__TooLate();
error MP__Already();
error MP__Missing();
error MP__TransferFailed();
error MP__Reentrancy();
error MP__Overflow();
error MP__Unauthorized();
error MP__Unsupported();
error MP__InvalidBytes();
error MP__ArrayMismatch();
error MP__TooLarge();
error MP__ZeroHash();

// ============================================================================
//  LIB: Minimal strings + hex (self-contained)
// ============================================================================

library MP_Strings {
    bytes16 private constant _HEX_SYMBOLS = "0123456789abcdef";

    function toString(uint256 value) internal pure returns (string memory) {
        if (value == 0) return "0";
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    function toHexString(uint256 value, uint256 fixedLengthBytes) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * fixedLengthBytes + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * fixedLengthBytes + 1; i > 1; --i) {
            buffer[i] = _HEX_SYMBOLS[value & 0xf];
            value >>= 4;
        }
        if (value != 0) revert MP__Overflow();
        return string(buffer);
    }

    function toHexString(address a) internal pure returns (string memory) {
        return toHexString(uint256(uint160(a)), 20);
    }
}

// ============================================================================
//  LIB: Bytes slicing + hashing helpers
// ============================================================================

library MP_Bytes {
    function slice(bytes memory data, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        if (start + len > data.length) revert MP__InvalidBytes();
        out = new bytes(len);
        for (uint256 i = 0; i < len; i++) out[i] = data[start + i];
    }

    function readUint256(bytes memory data, uint256 start) internal pure returns (uint256 v) {
        if (start + 32 > data.length) revert MP__InvalidBytes();
        assembly {
            v := mload(add(add(data, 0x20), start))
        }
    }

    function readBytes32(bytes memory data, uint256 start) internal pure returns (bytes32 v) {
        if (start + 32 > data.length) revert MP__InvalidBytes();
        assembly {
            v := mload(add(add(data, 0x20), start))
        }
    }

    function keccak(bytes memory data) internal pure returns (bytes32) {
        return keccak256(data);
    }

    function concat(bytes memory a, bytes memory b) internal pure returns (bytes memory out) {
        out = new bytes(a.length + b.length);
        uint256 i;
        for (; i < a.length; i++) out[i] = a[i];
        for (uint256 j = 0; j < b.length; j++) out[i + j] = b[j];
    }
}

// ============================================================================
//  LIB: SafeCast (narrowing with explicit checks)
// ============================================================================

library MP_SafeCast {
    function toUint64(uint256 x) internal pure returns (uint64) {
        if (x > type(uint64).max) revert MP__Overflow();
        return uint64(x);
    }

    function toUint32(uint256 x) internal pure returns (uint32) {
        if (x > type(uint32).max) revert MP__Overflow();
        return uint32(x);
    }

    function toUint16(uint256 x) internal pure returns (uint16) {
        if (x > type(uint16).max) revert MP__Overflow();
        return uint16(x);
    }

    function toUint8(uint256 x) internal pure returns (uint8) {
        if (x > type(uint8).max) revert MP__Overflow();
        return uint8(x);
    }
}

// ============================================================================
//  LIB: Merkle proof (single-leaf), with explicit hashing domain separation
// ============================================================================

library MP_Merkle {
    function verify(bytes32 root, bytes32 leaf, bytes32[] memory proof, uint256 index) internal pure returns (bool ok) {
        bytes32 computed = leaf;
        uint256 idx = index;
        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 p = proof[i];
            if ((idx & 1) == 1) computed = keccak256(abi.encodePacked(bytes1(0x01), p, computed));
            else computed = keccak256(abi.encodePacked(bytes1(0x01), computed, p));
            idx >>= 1;
        }
        return computed == root;
    }
}

// ============================================================================
//  LIB: ECDSA recover (no malleable signatures)
// ============================================================================

library MP_ECDSA {
    function recover(bytes32 digest, bytes memory signature) internal pure returns (address signer) {
        if (signature.length != 65) revert MP__BadSig();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        if (v < 27) v += 27;
        if (v != 27 && v != 28) revert MP__BadSig();
        // Enforce lower-s malleability per EIP-2
        if (uint256(s) > 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0) revert MP__BadSig();
        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert MP__BadSig();
    }
}

// ============================================================================
//  LIB: Bitmaps for sparse flags
// ============================================================================

library MP_Bitmap {
    function get(mapping(uint256 => uint256) storage bm, uint256 index) internal view returns (bool) {
        uint256 bucket = index >> 8;
        uint256 mask = 1 << (index & 0xff);
        return (bm[bucket] & mask) != 0;
    }

    function set(mapping(uint256 => uint256) storage bm, uint256 index) internal {
        uint256 bucket = index >> 8;
        uint256 mask = 1 << (index & 0xff);
        bm[bucket] |= mask;
    }

    function clear(mapping(uint256 => uint256) storage bm, uint256 index) internal {
        uint256 bucket = index >> 8;
        uint256 mask = 1 << (index & 0xff);
        bm[bucket] &= ~mask;
    }
}

// ============================================================================
//  INTERNAL: NonReentrant
// ============================================================================

abstract contract MP_Reentrancy {
    uint256 private _mpLock;

    modifier mpNonReentrant() {
        if (_mpLock != 0) revert MP__Reentrancy();
        _mpLock = 1;
        _;
        _mpLock = 0;
    }

    function _mpLocked() internal view returns (bool) {
        return _mpLock != 0;
    }
}

// ============================================================================
//  INTERNAL: Pausable
// ============================================================================

abstract contract MP_Pausable {
    event MP_PauseFlipped(bool paused, address indexed by, uint256 atBlock);
    bool public mpPaused;

    modifier mpWhenNotPaused() {
        if (mpPaused) revert MP__Paused();
        _;
    }

    function _mpSetPaused(bool v) internal {
        mpPaused = v;
        emit MP_PauseFlipped(v, msg.sender, block.number);
    }
}

// ============================================================================
//  INTERNAL: Two-step ownership
// ============================================================================

abstract contract MP_Owned2Step {
    event MP_OwnerTransferStarted(address indexed previousOwner, address indexed nextOwner, uint256 atBlock);
    event MP_OwnerTransferFinished(address indexed previousOwner, address indexed newOwner, uint256 atBlock);

    address public mpOwner;
    address public mpPendingOwner;

    modifier mpOnlyOwner() {
        if (msg.sender != mpOwner) revert MP__NotOwner();
        _;
    }

    function _mpInitOwner(address o) internal {
        if (o == address(0)) revert MP__BadAddress();
        mpOwner = o;
        emit MP_OwnerTransferFinished(address(0), o, block.number);
    }

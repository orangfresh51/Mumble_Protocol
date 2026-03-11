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

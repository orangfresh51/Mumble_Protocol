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

    function mpTransferOwnership(address nextOwner) external mpOnlyOwner {
        if (nextOwner == address(0)) revert MP__BadAddress();
        mpPendingOwner = nextOwner;
        emit MP_OwnerTransferStarted(mpOwner, nextOwner, block.number);
    }

    function mpAcceptOwnership() external {
        address pending = mpPendingOwner;
        if (msg.sender != pending) revert MP__Unauthorized();
        address prev = mpOwner;
        mpOwner = pending;
        mpPendingOwner = address(0);
        emit MP_OwnerTransferFinished(prev, pending, block.number);
    }
}

// ============================================================================
//  INTERNAL: Pull payments
// ============================================================================

abstract contract MP_PullPayments is MP_Reentrancy {
    mapping(address => uint256) internal _mpCredit;
    event MP_Credit(address indexed to, uint256 amount, bytes32 indexed reason, uint256 atBlock);
    event MP_Withdrawn(address indexed to, uint256 amount, uint256 atBlock);

    function mpCreditOf(address who) external view returns (uint256) {
        return _mpCredit[who];
    }

    function _mpAccrue(address to, uint256 amount, bytes32 reason) internal {
        if (to == address(0)) revert MP__BadAddress();
        if (amount == 0) return;
        _mpCredit[to] += amount;
        emit MP_Credit(to, amount, reason, block.number);
    }

    function mpWithdrawCredit(uint256 amount) external mpNonReentrant {
        uint256 bal = _mpCredit[msg.sender];
        if (amount == 0 || amount > bal) revert MP__BadAmount();
        _mpCredit[msg.sender] = bal - amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert MP__TransferFailed();
        emit MP_Withdrawn(msg.sender, amount, block.number);
    }
}

// ============================================================================
//  EIP-712 base
// ============================================================================

abstract contract MP_EIP712Domain {
    bytes32 internal immutable _MP_DOMAIN_SEPARATOR;
    uint256 internal immutable _MP_CACHED_CHAIN_ID;
    bytes32 internal immutable _MP_NAME_HASH;
    bytes32 internal immutable _MP_VERSION_HASH;

    bytes32 internal constant _MP_EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");

    constructor(string memory name, string memory version) {
        _MP_NAME_HASH = keccak256(bytes(name));
        _MP_VERSION_HASH = keccak256(bytes(version));
        _MP_CACHED_CHAIN_ID = block.chainid;
        _MP_DOMAIN_SEPARATOR = _buildDomainSeparator(_MP_EIP712_DOMAIN_TYPEHASH, _MP_NAME_HASH, _MP_VERSION_HASH);
    }

    function _buildDomainSeparator(bytes32 typeHash, bytes32 nameHash, bytes32 versionHash) private view returns (bytes32) {
        return keccak256(abi.encode(typeHash, nameHash, versionHash, block.chainid, address(this)));
    }

    function mpDomainSeparator() public view returns (bytes32) {
        if (block.chainid == _MP_CACHED_CHAIN_ID) return _MP_DOMAIN_SEPARATOR;
        return _buildDomainSeparator(_MP_EIP712_DOMAIN_TYPEHASH, _MP_NAME_HASH, _MP_VERSION_HASH);
    }

    function _hashTypedData(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", mpDomainSeparator(), structHash));
    }
}

// ============================================================================
//  INTERFACES (lean, for tooling)
// ============================================================================

interface IMP_MumbleView {
    function mpProtocolId() external view returns (bytes32);
    function mpRevision() external pure returns (uint256);
    function mpSealed() external view returns (bool);
    function mpGuardian() external view returns (address);
    function mpFeeVault() external view returns (address);
    function mpWindowConfig() external view returns (uint64 challengeWindow, uint64 revealWindow, uint64 escrowWindow);
}

// ============================================================================
//  MAIN CONTRACT
// ============================================================================

contract Mumble_Protocol is
    MP_Owned2Step,
    MP_Pausable,
    MP_PullPayments,
    MP_EIP712Domain,
    IMP_MumbleView
{
    using MP_SafeCast for uint256;
    using MP_Bitmap for mapping(uint256 => uint256);

    // ------------------------------------------------------------------------
    // Events (unique and chatty)
    // ------------------------------------------------------------------------

    event MP_GuardianSet(address indexed previous, address indexed current, uint256 atBlock);
    event MP_SealCast(address indexed by, bytes32 indexed sealId, uint256 atBlock);
    event MP_FeeVaultSet(address indexed previous, address indexed current, uint256 atBlock);
    event MP_WindowsSet(uint64 challengeWindow, uint64 revealWindow, uint64 escrowWindow, uint256 atBlock);
    event MP_RateSet(uint32 perEpoch, uint32 epochSeconds, uint256 atBlock);

    event MP_ExecutorStaked(address indexed executor, uint256 amount, uint256 stakeAfter, uint256 atBlock);
    event MP_ExecutorUnstaked(address indexed executor, uint256 amount, uint256 stakeAfter, uint256 atBlock);
    event MP_ExecutorSlashed(address indexed executor, address indexed to, uint256 amount, bytes32 indexed ticket, uint256 atBlock);

    event MP_MumbleOpened(
        uint256 indexed mumbleId,
        address indexed opener,
        bytes32 indexed commitment,
        uint64 deadline,
        uint96 maxFee,
        uint64 openedAt,
        bytes32 modelTag
    );

    event MP_MumbleFunded(uint256 indexed mumbleId, address indexed from, uint256 amount, uint256 newEscrow, uint256 atBlock);
    event MP_MumbleCancelled(uint256 indexed mumbleId, address indexed by, bytes32 indexed cancelId, uint256 atBlock);

    event MP_WhisperProposed(
        uint256 indexed mumbleId,
        bytes32 indexed whisperHash,
        address indexed executor,
        uint64 proposedAt,
        uint96 feeClaim
    );

    event MP_WhisperChallenged(
        uint256 indexed mumbleId,
        bytes32 indexed challengeHash,
        address indexed challenger,
        uint64 challengedAt
    );

    event MP_WhisperFinalized(
        uint256 indexed mumbleId,
        bytes32 indexed whisperHash,
        address indexed executor,
        uint64 finalizedAt,
        uint96 feePaid
    );

    event MP_RevealPublished(
        uint256 indexed mumbleId,
        bytes32 indexed revealHash,
        address indexed publisher,
        uint64 at
    );

    event MP_EscrowReclaimed(uint256 indexed mumbleId, address indexed to, uint256 amount, uint64 at);
    event MP_FeeSwept(address indexed to, uint256 amount, bytes32 indexed sweepId, uint256 atBlock);
    event MP_FallbackIn(address indexed from, uint256 amount, uint256 atBlock);

    // ------------------------------------------------------------------------
    // Types
    // ------------------------------------------------------------------------

    struct Mumble {
        address opener;
        uint96 maxFee;
        uint64 deadline;
        uint64 openedAt;
        bytes32 commitment;
        bytes32 modelTag;
        uint256 escrow;
        // whisper data
        address executor;
        uint96 feeClaim;
        uint64 proposedAt;
        bytes32 whisperHash;
        bool finalized;
        bool cancelled;
    }

    struct RateLimit {
        uint32 perEpoch;
        uint32 epochSeconds;
    }

    // ------------------------------------------------------------------------
    // Constants (randomized + distinctive)
    // ------------------------------------------------------------------------

    uint256 public constant MP_REVISION = 7;

    bytes32 public constant MP_PROTOCOL_ID =
        keccak256("Mumble_Protocol::HUSH_RELAY::rev7::horizon/argon/silt");

    bytes32 public constant MP_MUMBLE_TYPEHASH =
        keccak256("MumbleOpen(bytes32 commitment,bytes32 modelTag,uint64 deadline,uint96 maxFee,address opener,uint256 nonce)");

    bytes32 public constant MP_WHISPER_TYPEHASH =
        keccak256("Whisper(uint256 mumbleId,bytes32 whisperHash,uint96 feeClaim,address executor,uint256 stakeNonce,uint64 proposedAt)");

    bytes32 public constant MP_REVEAL_TYPEHASH =
        keccak256("Reveal(uint256 mumbleId,bytes32 revealHash,address publisher,uint64 at)");

    bytes32 public constant MP_CHALLENGE_TYPEHASH =
        keccak256("Challenge(uint256 mumbleId,bytes32 challengeHash,address challenger,uint64 at)");

    bytes32 public constant MP_SEAL_SALT =
        0x0a7f9b3d7a2e4c9b1f4e6d8c2a9f7b3d0c1e8a7f9b3d7a2e4c9b1f4e6d8c2a9f;

    bytes32 public constant MP_RNG_SALT =
        0x9e3c61a2b7d4f0831c5a8e9f0d2b4a6c8e0f1a3b5c7d9e2f4a6c8e0f1a3b5c7d;

    bytes32 public constant MP_TICKET_SALT =
        0x6c2f1b9d4e8a0c7f3a2d9b1e4c6f8a0d2b5e7c9a1d3f5b7e9c0a2d4f6b8e0c1a;

    uint256 public constant MP_MAX_BATCH = 37;
    uint256 public constant MP_MAX_PROOF_BYTES = 4096;
    uint256 public constant MP_MAX_NOTE_BYTES = 1536;

    // ------------------------------------------------------------------------
    // Immutable bootstrap + roles
    // ------------------------------------------------------------------------

    address public immutable mpBootstrap;
    address public immutable mpFeeVault;

    // ------------------------------------------------------------------------
    // Governance / safety state
    // ------------------------------------------------------------------------

    address public mpGuardian;
    bool public mpSealedFlag;
    bytes32 public mpSealId;

    uint64 private _mpChallengeWindow;
    uint64 private _mpRevealWindow;
    uint64 private _mpEscrowWindow;

    RateLimit private _mpOpenRate;

    // ------------------------------------------------------------------------
    // Storage: mumbles + flags + balances
    // ------------------------------------------------------------------------

    Mumble[] private _mumbles;
    uint256 public mpTotalFeesAccrued;
    uint256 public mpTotalFeesPaid;

    // opener => nonce used
    mapping(address => uint256) public mpNonce;

    // mumbleId => challenged flag (bitmap)
    mapping(uint256 => uint256) private _mpChallenged;

    // mumbleId => reveal published flag (bitmap)
    mapping(uint256 => uint256) private _mpRevealed;

    // per-epoch rate limiting: opener => epochId => count
    mapping(address => mapping(uint256 => uint32)) private _mpOpenCount;

    // executor staking
    mapping(address => uint256) public mpStake;
    mapping(address => uint256) public mpStakeNonce;


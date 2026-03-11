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

    // ------------------------------------------------------------------------
    // Constructor
    // ------------------------------------------------------------------------

    constructor()
        MP_EIP712Domain("Mumble_Protocol", "7.0.0-hush")
    {
        // No user-supplied addresses; all roles bootstrap to deployer.
        address deployer = msg.sender;
        _mpInitOwner(deployer);
        mpGuardian = deployer;
        mpBootstrap = deployer;

        // Fee vault deterministically derived; avoids embedded address literals.
        mpFeeVault = address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0x7f),
            MP_PROTOCOL_ID,
            MP_RNG_SALT,
            block.chainid,
            deployer,
            address(this)
        )))));

        // Windows (randomized within sane ranges)
        _mpChallengeWindow = uint64(19 hours + 37 minutes);
        _mpRevealWindow = uint64(2 days + 3 hours + 11 minutes);
        _mpEscrowWindow = uint64(10 days + 7 hours + 29 minutes);

        // Rate limits
        _mpOpenRate = RateLimit({
            perEpoch: uint32(17),
            epochSeconds: uint32(47 minutes)
        });

        // Seed an empty first slot to make mumbleId non-zero in UIs.
        _mumbles.push(Mumble({
            opener: address(0),
            maxFee: 0,
            deadline: 0,
            openedAt: 0,
            commitment: bytes32(0),
            modelTag: bytes32(0),
            escrow: 0,
            executor: address(0),
            feeClaim: 0,
            proposedAt: 0,
            whisperHash: bytes32(0),
            finalized: true,
            cancelled: true
        }));
    }

    // ------------------------------------------------------------------------
    // Modifiers
    // ------------------------------------------------------------------------

    modifier mpOnlyGuardian() {
        if (msg.sender != mpGuardian) revert MP__NotGuardian();
        _;
    }

    modifier mpWhenNotSealed() {
        if (mpSealedFlag) revert MP__Sealed();
        _;
    }

    // ------------------------------------------------------------------------
    // IMP_MumbleView
    // ------------------------------------------------------------------------

    function mpProtocolId() external pure returns (bytes32) {
        return MP_PROTOCOL_ID;
    }

    function mpRevision() external pure returns (uint256) {
        return MP_REVISION;
    }

    function mpSealed() external view returns (bool) {
        return mpSealedFlag;
    }

    function mpGuardian() external view returns (address) {
        return mpGuardian;
    }

    function mpFeeVault() external view returns (address) {
        return mpFeeVault;
    }

    function mpWindowConfig() external view returns (uint64 challengeWindow, uint64 revealWindow, uint64 escrowWindow) {
        return (_mpChallengeWindow, _mpRevealWindow, _mpEscrowWindow);
    }

    // ------------------------------------------------------------------------
    // Governance / safety
    // ------------------------------------------------------------------------

    function mpSetGuardian(address g) external mpOnlyOwner {
        if (g == address(0)) revert MP__BadAddress();
        address prev = mpGuardian;
        mpGuardian = g;
        emit MP_GuardianSet(prev, g, block.number);
    }

    function mpSetPaused(bool v) external mpOnlyGuardian {
        _mpSetPaused(v);
    }

    function mpCastSeal(bytes32 sealId) external mpOnlyGuardian {
        if (sealId == bytes32(0)) revert MP__ZeroHash();
        mpSealedFlag = true;
        mpSealId = sealId;
        emit MP_SealCast(msg.sender, sealId, block.number);
    }

    function mpSetWindows(uint64 challengeWindow, uint64 revealWindow, uint64 escrowWindow) external mpOnlyOwner {
        if (challengeWindow < 1 hours || challengeWindow > 14 days) revert MP__BadWindow();
        if (revealWindow < 1 hours || revealWindow > 30 days) revert MP__BadWindow();
        if (escrowWindow < 1 days || escrowWindow > 365 days) revert MP__BadWindow();
        _mpChallengeWindow = challengeWindow;
        _mpRevealWindow = revealWindow;
        _mpEscrowWindow = escrowWindow;
        emit MP_WindowsSet(challengeWindow, revealWindow, escrowWindow, block.number);
    }

    function mpSetOpenRate(uint32 perEpoch, uint32 epochSeconds) external mpOnlyOwner {
        if (perEpoch == 0) revert MP__BadAmount();
        if (epochSeconds < 60 || epochSeconds > 7 days) revert MP__BadWindow();
        _mpOpenRate = RateLimit({perEpoch: perEpoch, epochSeconds: epochSeconds});
        emit MP_RateSet(perEpoch, epochSeconds, block.number);
    }

    // ------------------------------------------------------------------------
    // Staking
    // ------------------------------------------------------------------------

    function mpStakeExecutor() external payable mpWhenNotPaused mpWhenNotSealed mpNonReentrant {
        if (msg.value == 0) revert MP__BadAmount();
        uint256 afterStake = mpStake[msg.sender] + msg.value;
        mpStake[msg.sender] = afterStake;
        emit MP_ExecutorStaked(msg.sender, msg.value, afterStake, block.number);
    }

    function mpUnstakeExecutor(uint256 amount) external mpWhenNotPaused mpNonReentrant {
        if (amount == 0) revert MP__BadAmount();
        uint256 st = mpStake[msg.sender];
        if (amount > st) revert MP__BadAmount();
        mpStake[msg.sender] = st - amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        if (!ok) revert MP__TransferFailed();
        emit MP_ExecutorUnstaked(msg.sender, amount, st - amount, block.number);
    }

    function mpSlashExecutor(address executor, uint256 amount, address to, bytes32 ticket) external mpOnlyGuardian mpNonReentrant {
        if (executor == address(0) || to == address(0)) revert MP__BadAddress();
        if (amount == 0) revert MP__BadAmount();
        if (ticket == bytes32(0)) revert MP__ZeroHash();
        uint256 st = mpStake[executor];
        if (amount > st) amount = st;
        mpStake[executor] = st - amount;
        _mpAccrue(to, amount, keccak256(abi.encodePacked(MP_TICKET_SALT, ticket, executor)));
        emit MP_ExecutorSlashed(executor, to, amount, ticket, block.number);
    }

    // ------------------------------------------------------------------------
    // Opening: Mumble commitments
    // ------------------------------------------------------------------------

    function mpOpenMumble(
        bytes32 commitment,
        bytes32 modelTag,
        uint64 deadline,
        uint96 maxFee
    ) external mpWhenNotPaused mpWhenNotSealed returns (uint256 mumbleId) {
        if (commitment == bytes32(0) || modelTag == bytes32(0)) revert MP__ZeroHash();
        if (deadline <= block.timestamp) revert MP__TooLate();
        if (maxFee == 0) revert MP__BadAmount();

        _mpApplyOpenRate(msg.sender);

        mumbleId = _mumbles.length;
        _mumbles.push(Mumble({
            opener: msg.sender,
            maxFee: maxFee,
            deadline: deadline,
            openedAt: uint64(block.timestamp),
            commitment: commitment,
            modelTag: modelTag,
            escrow: 0,
            executor: address(0),
            feeClaim: 0,
            proposedAt: 0,
            whisperHash: bytes32(0),
            finalized: false,
            cancelled: false
        }));

        emit MP_MumbleOpened(
            mumbleId,
            msg.sender,
            commitment,
            deadline,
            maxFee,
            uint64(block.timestamp),
            modelTag
        );
    }

    function mpOpenMumbleSigned(
        bytes32 commitment,
        bytes32 modelTag,
        uint64 deadline,
        uint96 maxFee,
        address opener,
        bytes memory signature
    ) external mpWhenNotPaused mpWhenNotSealed returns (uint256 mumbleId) {
        if (opener == address(0)) revert MP__BadAddress();
        if (commitment == bytes32(0) || modelTag == bytes32(0)) revert MP__ZeroHash();
        if (deadline <= block.timestamp) revert MP__TooLate();
        if (maxFee == 0) revert MP__BadAmount();

        uint256 nonce = mpNonce[opener];
        bytes32 structHash = keccak256(abi.encode(
            MP_MUMBLE_TYPEHASH,
            commitment,
            modelTag,
            deadline,
            maxFee,
            opener,
            nonce
        ));
        bytes32 digest = _hashTypedData(structHash);
        address signer = MP_ECDSA.recover(digest, signature);
        if (signer != opener) revert MP__BadSig();

        mpNonce[opener] = nonce + 1;
        _mpApplyOpenRate(opener);

        mumbleId = _mumbles.length;
        _mumbles.push(Mumble({
            opener: opener,
            maxFee: maxFee,
            deadline: deadline,
            openedAt: uint64(block.timestamp),
            commitment: commitment,
            modelTag: modelTag,
            escrow: 0,
            executor: address(0),
            feeClaim: 0,
            proposedAt: 0,
            whisperHash: bytes32(0),
            finalized: false,
            cancelled: false
        }));

        emit MP_MumbleOpened(
            mumbleId,
            opener,
            commitment,
            deadline,
            maxFee,
            uint64(block.timestamp),
            modelTag
        );
    }

    function mpFundMumble(uint256 mumbleId) external payable mpWhenNotPaused mpNonReentrant {
        if (msg.value == 0) revert MP__BadAmount();
        Mumble storage m = _mpGetMumble(mumbleId);
        if (m.cancelled || m.finalized) revert MP__BadState();
        if (block.timestamp > m.deadline) revert MP__TooLate();
        m.escrow += msg.value;
        emit MP_MumbleFunded(mumbleId, msg.sender, msg.value, m.escrow, block.number);
    }

    function mpCancelMumble(uint256 mumbleId, bytes32 cancelId) external mpWhenNotPaused mpNonReentrant {
        if (cancelId == bytes32(0)) revert MP__ZeroHash();
        Mumble storage m = _mpGetMumble(mumbleId);
        if (msg.sender != m.opener) revert MP__Unauthorized();
        if (m.cancelled) revert MP__Already();
        if (m.finalized) revert MP__BadState();
        if (m.executor != address(0)) revert MP__BadState();
        m.cancelled = true;
        uint256 amount = m.escrow;
        m.escrow = 0;
        if (amount != 0) _mpAccrue(m.opener, amount, keccak256(abi.encodePacked("CANCEL", cancelId, mumbleId)));
        emit MP_MumbleCancelled(mumbleId, msg.sender, cancelId, block.number);
    }

    // ------------------------------------------------------------------------
    // Whisper: propose + challenge + finalize
    // ------------------------------------------------------------------------

    function mpProposeWhisper(
        uint256 mumbleId,
        bytes32 whisperHash,
        uint96 feeClaim,
        uint64 proposedAt,
        bytes memory executorSig
    ) external mpWhenNotPaused mpWhenNotSealed {
        if (whisperHash == bytes32(0)) revert MP__ZeroHash();
        Mumble storage m = _mpGetMumble(mumbleId);
        if (m.cancelled || m.finalized) revert MP__BadState();
        if (block.timestamp > m.deadline) revert MP__TooLate();
        if (m.executor != address(0)) revert MP__Already();
        if (feeClaim == 0 || feeClaim > m.maxFee) revert MP__BadAmount();
        if (proposedAt == 0) proposedAt = uint64(block.timestamp);
        if (proposedAt > block.timestamp + 2 minutes) revert MP__BadWindow();

        // Require the executor to sign the whisper proposal (prevents griefing).
        uint256 stakeNonce = mpStakeNonce[msg.sender];
        bytes32 structHash = keccak256(abi.encode(
            MP_WHISPER_TYPEHASH,
            mumbleId,
            whisperHash,
            feeClaim,
            msg.sender,
            stakeNonce,
            proposedAt
        ));
        bytes32 digest = _hashTypedData(structHash);
        address signer = MP_ECDSA.recover(digest, executorSig);
        if (signer != msg.sender) revert MP__BadSig();

        m.executor = msg.sender;
        m.feeClaim = feeClaim;
        m.proposedAt = proposedAt;
        m.whisperHash = whisperHash;
        mpStakeNonce[msg.sender] = stakeNonce + 1;

        emit MP_WhisperProposed(mumbleId, whisperHash, msg.sender, proposedAt, feeClaim);
    }

    function mpChallengeWhisper(
        uint256 mumbleId,
        bytes32 challengeHash
    ) external mpWhenNotPaused {
        if (challengeHash == bytes32(0)) revert MP__ZeroHash();
        Mumble storage m = _mpGetMumble(mumbleId);
        if (m.cancelled || m.finalized) revert MP__BadState();
        if (m.executor == address(0)) revert MP__Missing();
        if (block.timestamp < m.proposedAt) revert MP__BadState();
        if (block.timestamp > uint256(m.proposedAt) + _mpChallengeWindow) revert MP__TooLate();
        if (_mpChallenged.get(mumbleId)) revert MP__Already();
        _mpChallenged.set(mumbleId);
        emit MP_WhisperChallenged(mumbleId, challengeHash, msg.sender, uint64(block.timestamp));
    }

    function mpFinalizeWhisper(uint256 mumbleId) external mpWhenNotPaused mpNonReentrant {
        Mumble storage m = _mpGetMumble(mumbleId);
        if (m.cancelled || m.finalized) revert MP__BadState();
        if (m.executor == address(0)) revert MP__Missing();
        if (block.timestamp < m.proposedAt) revert MP__BadState();
        if (block.timestamp <= uint256(m.proposedAt) + _mpChallengeWindow) revert MP__TooEarly();
        if (_mpChallenged.get(mumbleId)) revert MP__BadState();

        m.finalized = true;
        uint96 fee = m.feeClaim;

        uint256 escrow = m.escrow;
        uint256 pay = escrow < fee ? escrow : fee;
        uint256 refund = escrow - pay;
        m.escrow = 0;

        if (pay != 0) {
            mpTotalFeesPaid += pay;
            _mpAccrue(m.executor, pay, keccak256(abi.encodePacked("FEE", mumbleId, m.whisperHash)));
        }
        if (refund != 0) _mpAccrue(m.opener, refund, keccak256(abi.encodePacked("REFUND", mumbleId, m.commitment)));

        emit MP_WhisperFinalized(mumbleId, m.whisperHash, m.executor, uint64(block.timestamp), uint96(pay));
    }

    // ------------------------------------------------------------------------
    // Reveal: optional publication of additional material hashes
    // ------------------------------------------------------------------------

    function mpPublishReveal(uint256 mumbleId, bytes32 revealHash, uint64 at, bytes memory publisherSig)
        external
        mpWhenNotPaused
    {
        if (revealHash == bytes32(0)) revert MP__ZeroHash();
        Mumble storage m = _mpGetMumble(mumbleId);
        if (m.cancelled) revert MP__BadState();
        if (m.executor == address(0)) revert MP__Missing();
        if (at == 0) at = uint64(block.timestamp);
        if (at > block.timestamp + 2 minutes) revert MP__BadWindow();
        if (at < m.openedAt) revert MP__BadWindow();
        if (at > uint256(m.openedAt) + _mpRevealWindow) revert MP__TooLate();
        if (_mpRevealed.get(mumbleId)) revert MP__Already();

        // Require the opener to approve reveal publication, unless the opener is publishing.
        if (msg.sender != m.opener) {
            bytes32 structHash = keccak256(abi.encode(
                MP_REVEAL_TYPEHASH,
                mumbleId,
                revealHash,
                msg.sender,
                at
            ));
            bytes32 digest = _hashTypedData(structHash);
            address signer = MP_ECDSA.recover(digest, publisherSig);
            if (signer != m.opener) revert MP__BadSig();
        } else {
            if (publisherSig.length != 0) {
                // Accept empty signature only; anything else risks accidental confusion.
                revert MP__BadSig();
            }
        }

        _mpRevealed.set(mumbleId);
        emit MP_RevealPublished(mumbleId, revealHash, msg.sender, at);
    }

    // ------------------------------------------------------------------------
    // Escrow expiry reclaim (no executor: after deadline + escrow window)
    // ------------------------------------------------------------------------

    function mpReclaimExpiredEscrow(uint256 mumbleId) external mpWhenNotPaused mpNonReentrant {
        Mumble storage m = _mpGetMumble(mumbleId);
        if (m.cancelled) revert MP__BadState();
        if (m.executor != address(0)) revert MP__BadState();
        if (block.timestamp <= m.deadline) revert MP__TooEarly();
        if (block.timestamp <= uint256(m.deadline) + _mpEscrowWindow) revert MP__TooEarly();
        if (m.escrow == 0) revert MP__BadAmount();
        uint256 amount = m.escrow;
        m.escrow = 0;
        _mpAccrue(m.opener, amount, keccak256(abi.encodePacked("EXPIRE", mumbleId, m.deadline)));
        emit MP_EscrowReclaimed(mumbleId, m.opener, amount, uint64(block.timestamp));
    }

    // ------------------------------------------------------------------------
    // Fee vault sweeping (collect dust from direct sends)
    // ------------------------------------------------------------------------

    function mpSweepToFeeVault(uint256 amount, bytes32 sweepId) external mpOnlyGuardian mpNonReentrant {
        if (sweepId == bytes32(0)) revert MP__ZeroHash();
        if (amount == 0) revert MP__BadAmount();
        uint256 bal = address(this).balance;
        if (amount > bal) amount = bal;
        (bool ok,) = payable(mpFeeVault).call{value: amount}("");
        if (!ok) revert MP__TransferFailed();
        emit MP_FeeSwept(mpFeeVault, amount, sweepId, block.number);
    }

    // ------------------------------------------------------------------------
    // Views (high-signal + many small helpers; deliberately not patterned like your others)
    // ------------------------------------------------------------------------

    function mpMumbleCount() external view returns (uint256) {
        return _mumbles.length;
    }

    function mpExists(uint256 mumbleId) external view returns (bool) {
        return mumbleId != 0 && mumbleId < _mumbles.length;
    }

    function mpMumble(uint256 mumbleId) external view returns (Mumble memory) {
        return _mpGetMumble(mumbleId);
    }

    function mpOpener(uint256 mumbleId) external view returns (address) {
        return _mpGetMumble(mumbleId).opener;
    }

    function mpCommitment(uint256 mumbleId) external view returns (bytes32) {
        return _mpGetMumble(mumbleId).commitment;
    }

    function mpModelTag(uint256 mumbleId) external view returns (bytes32) {
        return _mpGetMumble(mumbleId).modelTag;
    }

    function mpMaxFee(uint256 mumbleId) external view returns (uint96) {
        return _mpGetMumble(mumbleId).maxFee;
    }

    function mpDeadline(uint256 mumbleId) external view returns (uint64) {
        return _mpGetMumble(mumbleId).deadline;
    }

    function mpOpenedAt(uint256 mumbleId) external view returns (uint64) {
        return _mpGetMumble(mumbleId).openedAt;
    }

    function mpEscrow(uint256 mumbleId) external view returns (uint256) {
        return _mpGetMumble(mumbleId).escrow;
    }

    function mpExecutor(uint256 mumbleId) external view returns (address) {
        return _mpGetMumble(mumbleId).executor;
    }

    function mpWhisperHash(uint256 mumbleId) external view returns (bytes32) {
        return _mpGetMumble(mumbleId).whisperHash;
    }

    function mpFeeClaim(uint256 mumbleId) external view returns (uint96) {
        return _mpGetMumble(mumbleId).feeClaim;
    }

    function mpProposedAt(uint256 mumbleId) external view returns (uint64) {
        return _mpGetMumble(mumbleId).proposedAt;
    }

    function mpFinalized(uint256 mumbleId) external view returns (bool) {
        return _mpGetMumble(mumbleId).finalized;
    }

    function mpCancelled(uint256 mumbleId) external view returns (bool) {
        return _mpGetMumble(mumbleId).cancelled;
    }

    function mpChallenged(uint256 mumbleId) external view returns (bool) {
        return _mpChallenged.get(mumbleId);
    }

    function mpRevealed(uint256 mumbleId) external view returns (bool) {
        return _mpRevealed.get(mumbleId);
    }

    function mpOpenRate() external view returns (uint32 perEpoch, uint32 epochSeconds) {
        RateLimit memory r = _mpOpenRate;
        return (r.perEpoch, r.epochSeconds);
    }

    function mpWindows() external view returns (uint64 challengeWindow, uint64 revealWindow, uint64 escrowWindow) {
        return (_mpChallengeWindow, _mpRevealWindow, _mpEscrowWindow);
    }

    function mpStats() external view returns (
        uint256 mumbleCount,
        uint256 contractBalance,
        uint256 feesPaid,
        uint256 totalCreditOutstanding,
        bool paused_,
        bool sealed_
    ) {
        mumbleCount = _mumbles.length;
        contractBalance = address(this).balance;
        feesPaid = mpTotalFeesPaid;
        totalCreditOutstanding = _mpTotalCredits();
        paused_ = mpPaused;
        sealed_ = mpSealedFlag;
    }

    function mpDomainBytes() external view returns (bytes32 nameHash, bytes32 versionHash, bytes32 domainSeparator) {

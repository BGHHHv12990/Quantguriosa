// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

/*
    Quantguriosa — "liquidity with a memory".

    A self-contained, DEX-style automated market maker with:
    - deterministic pool ids (no factory clones),
    - vault-less reserves held in the pool contract,
    - dynamic fee that reacts to short-horizon volatility (oracle ring buffer),
    - LP share token (internal ERC20) with EIP-2612 permit,
    - strict reentrancy + pause lanes + bounded loops,
    - explicit errors/events (unique naming).

    Not affiliated with any existing DEX implementation.
*/

// =============================================================
// Interfaces
// =============================================================

interface IERC20Like {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function allowance(address, address) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function decimals() external view returns (uint8);
}

interface IERC1271Like {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4 magicValue);
}

interface IQGFlashCallee {
    /// @notice Called after flash assets are transferred.
    /// @dev Must return assets + fees to the pool before returning.
    function qgFlashCallback(address initiator, uint256 amount0, uint256 amount1, bytes calldata data) external;
}

// =============================================================
// Libraries (purposefully compact + non-OZ)
// =============================================================

library QGAddress {
    error QGADDR_NotContract();
    error QGADDR_CallFailed();
    error QGADDR_BadReturn();

    function isContract(address a) internal view returns (bool) {
        return a.code.length != 0;
    }

    function safeTransferETH(address to, uint256 amount) internal {
        (bool ok, ) = to.call{value: amount}("");
        if (!ok) revert QGADDR_CallFailed();
    }

    function safeTransfer(IERC20Like t, address to, uint256 amount) internal {
        bytes memory data = abi.encodeWithSelector(t.transfer.selector, to, amount);
        bytes memory ret = _call(address(t), data);
        if (ret.length != 0 && !abi.decode(ret, (bool))) revert QGADDR_BadReturn();
    }

    function safeTransferFrom(IERC20Like t, address from, address to, uint256 amount) internal {
        bytes memory data = abi.encodeWithSelector(t.transferFrom.selector, from, to, amount);
        bytes memory ret = _call(address(t), data);
        if (ret.length != 0 && !abi.decode(ret, (bool))) revert QGADDR_BadReturn();
    }

    function safeApprove(IERC20Like t, address spender, uint256 amount) internal {
        bytes memory data = abi.encodeWithSelector(t.approve.selector, spender, amount);
        bytes memory ret = _call(address(t), data);
        if (ret.length != 0 && !abi.decode(ret, (bool))) revert QGADDR_BadReturn();
    }

    function _call(address target, bytes memory data) private returns (bytes memory ret) {
        if (!isContract(target)) revert QGADDR_NotContract();
        (bool ok, bytes memory out) = target.call(data);
        if (!ok) revert QGADDR_CallFailed();
        return out;
    }
}

library QGMath {
    error QGM_Overflow();
    error QGM_Underflow();
    error QGM_DivZero();

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function absDiff(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? (a - b) : (b - a);
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }

    function mulDiv(uint256 x, uint256 y, uint256 d) internal pure returns (uint256 z) {
        if (d == 0) revert QGM_DivZero();
        // 512-bit multiply then divide. (Not copied from OZ; simplified FullMath style.)
        uint256 prod0;
        uint256 prod1;
        assembly {
            let mm := mulmod(x, y, not(0))
            prod0 := mul(x, y)
            prod1 := sub(sub(mm, prod0), lt(mm, prod0))
        }
        if (prod1 == 0) return prod0 / d;
        // Ensure result < 2^256 and denominator > prod1
        if (d <= prod1) revert QGM_Overflow();

        // Subtract remainder to make division exact
        uint256 rem;
        assembly {
            rem := mulmod(x, y, d)
        }
        assembly {
            prod1 := sub(prod1, gt(rem, prod0))
            prod0 := sub(prod0, rem)
        }

        // Factor powers of two out of denominator
        uint256 twos = d & (~d + 1);
        assembly {
            d := div(d, twos)
            prod0 := div(prod0, twos)
            twos := add(div(sub(0, twos), twos), 1)
        }
        prod0 |= prod1 * twos;

        // Inverse of d mod 2^256
        uint256 inv = (3 * d) ^ 2;
        unchecked {
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
            inv *= 2 - d * inv;
        }
        return prod0 * inv;
    }

    function sqrt(uint256 a) internal pure returns (uint256) {
        if (a == 0) return 0;
        uint256 x = 1 << (log2(a) >> 1);
        unchecked {
            for (uint256 i = 0; i < 7; i++) {
                x = (x + a / x) >> 1;
            }
            uint256 y = a / x;
            return x < y ? x : y;
        }
    }

    function log2(uint256 x) internal pure returns (uint256 r) {
        unchecked {
            if (x >> 128 != 0) {
                x >>= 128;
                r += 128;
            }
            if (x >> 64 != 0) {
                x >>= 64;
                r += 64;
            }
            if (x >> 32 != 0) {
                x >>= 32;
                r += 32;
            }
            if (x >> 16 != 0) {
                x >>= 16;
                r += 16;
            }
            if (x >> 8 != 0) {
                x >>= 8;
                r += 8;
            }
            if (x >> 4 != 0) {
                x >>= 4;
                r += 4;
            }
            if (x >> 2 != 0) {
                x >>= 2;
                r += 2;
            }
            if (x >> 1 != 0) {
                r += 1;
            }
        }
    }
}

library QGECDSA {
    error QGE_BadSigLength();
    error QGE_BadS();
    error QGE_BadV();

    // secp256k1n/2 (same constant, different naming)
    uint256 internal constant _HALF_N =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    function recover(bytes32 digest, bytes calldata sig) internal pure returns (address signer) {
        if (sig.length != 65) revert QGE_BadSigLength();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := calldataload(sig.offset)
            s := calldataload(add(sig.offset, 32))
            v := byte(0, calldataload(add(sig.offset, 64)))
        }
        if (uint256(s) > _HALF_N) revert QGE_BadS();
        if (v != 27 && v != 28) revert QGE_BadV();
        return ecrecover(digest, v, r, s);
    }

    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
}

abstract contract QGEIP712 {
    bytes32 private immutable _NAME_HASH;
    bytes32 private immutable _VER_HASH;
    bytes32 private immutable _DOMAIN_TYPEHASH;

    constructor(string memory name, string memory version) {
        _NAME_HASH = keccak256(bytes(name));
        _VER_HASH = keccak256(bytes(version));
        _DOMAIN_TYPEHASH = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
        );
    }

    function _domainSeparator() internal view returns (bytes32) {
        return keccak256(abi.encode(_DOMAIN_TYPEHASH, _NAME_HASH, _VER_HASH, block.chainid, address(this)));
    }

    function _hashTyped(bytes32 structHash) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", _domainSeparator(), structHash));
    }
}

abstract contract QGReentrancy {
    error QGR_Reentered();
    uint256 private _g;
    modifier nonReentrant() {
        if (_g == 2) revert QGR_Reentered();
        _g = 2;
        _;
        _g = 1;
    }
}

// =============================================================
// LP Token (internal ERC20) with EIP-2612 permit
// =============================================================

abstract contract QGLPToken is QGEIP712 {
    error QGLP_Zero();
    error QGLP_Insufficient();
    error QGLP_Allowance();
    error QGLP_Expired();
    error QGLP_BadSig();

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Approval(address indexed owner, address indexed spender, uint256 amount);

    string public name;
    string public symbol;
    uint8 public immutable decimals;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    // permit
    mapping(address => uint256) public nonces;
    bytes32 public immutable PERMIT_TYPEHASH;

    constructor(string memory name_, string memory symbol_, uint8 decimals_)
        QGEIP712(name_, "qg.lp.0.4.9")
    {
        name = name_;
        symbol = symbol_;
        decimals = decimals_;
        PERMIT_TYPEHASH =
            keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        _approve(msg.sender, spender, amount);
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        uint256 a = allowance[from][msg.sender];
        if (a != type(uint256).max) {
            if (a < amount) revert QGLP_Allowance();
            unchecked {
                allowance[from][msg.sender] = a - amount;
            }
        }
        _transfer(from, to, amount);
        return true;
    }

    function permit(
        address owner,
        address spender,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        if (owner == address(0) || spender == address(0)) revert QGLP_Zero();
        if (block.timestamp > deadline) revert QGLP_Expired();

        uint256 nonce = nonces[owner]++;
        bytes32 structHash = keccak256(abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonce, deadline));
        bytes32 digest = _hashTyped(structHash);

        address recovered = ecrecover(digest, v, r, s);
        if (recovered == address(0) || recovered != owner) revert QGLP_BadSig();

        _approve(owner, spender, value);
    }

    function _approve(address owner, address spender, uint256 amount) internal {
        allowance[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        if (to == address(0)) revert QGLP_Zero();
        uint256 b = balanceOf[from];
        if (b < amount) revert QGLP_Insufficient();
        unchecked {
            balanceOf[from] = b - amount;
            balanceOf[to] += amount;
        }
        emit Transfer(from, to, amount);
    }

    function _mint(address to, uint256 amount) internal {
        if (to == address(0)) revert QGLP_Zero();
        totalSupply += amount;
        unchecked {
            balanceOf[to] += amount;
        }
        emit Transfer(address(0), to, amount);
    }

    function _burn(address from, uint256 amount) internal {
        uint256 b = balanceOf[from];
        if (b < amount) revert QGLP_Insufficient();
        unchecked {
            balanceOf[from] = b - amount;
            totalSupply -= amount;
        }
        emit Transfer(from, address(0), amount);
    }
}

// =============================================================
// Quantguriosa Pool (single pool contract; deploy one per pair)
// =============================================================

contract Quantguriosa is QGLPToken, QGReentrancy {
    using QGAddress for IERC20Like;
    using QGMath for uint256;

    // -----------------------------
    // Custom errors (unique prefixes)
    // -----------------------------
    error QG_Unauthorized();
    error QG_Paused();
    error QG_Same();
    error QG_Zero();
    error QG_Bounds();
    error QG_NotReady();
    error QG_Stale();
    error QG_FeeTooHigh();
    error QG_Slippage();
    error QG_BadToken();
    error QG_ReserveSkew();
    error QG_OracleFull();
    error QG_OracleEmpty();
    error QG_BadSig();
    error QG_TooLarge();
    error QG_NoLiquidity();
    error QG_KInvariant();
    error QG_Dupe();
    error QG_FlashDebt();
    error QG_CallbackOnly();
    error QG_ProtocolOff();

    // -----------------------------
    // Events
    // -----------------------------
    event QG_AdminProposed(address indexed admin, address indexed proposed);
    event QG_AdminAccepted(address indexed oldAdmin, address indexed newAdmin);
    event QG_GuardianSet(address indexed oldGuardian, address indexed newGuardian);
    event QG_PauseSet(bool paused);

    event QG_Minted(address indexed provider, uint256 amount0In, uint256 amount1In, uint256 sharesOut, address indexed to);
    event QG_Burned(address indexed provider, uint256 sharesIn, uint256 amount0Out, uint256 amount1Out, address indexed to);
    event QG_Swapped(
        address indexed trader,
        address indexed tokenIn,
        uint256 amountIn,
        address indexed tokenOut,
        uint256 amountOut,
        uint24 feeBps,
        bytes16 tag
    );
    event QG_Skimmed(address indexed to, uint256 excess0, uint256 excess1);
    event QG_OraclePushed(uint32 indexed idx, uint64 ts, uint128 r0, uint128 r1, uint32 qk, uint32 vol);
    event QG_ParamsSet(uint24 feeBaseBps, uint24 feeMaxBps, uint32 gammaE8, uint32 oraclePeriod, uint16 oracleSlots);
    event QG_ProtocolSet(address indexed feeTo, uint16 protocolShareBps, bool on);
    event QG_ProtocolCollected(address indexed feeTo, uint256 amount0, uint256 amount1);
    event QG_Flash(address indexed initiator, address indexed receiver, uint256 amount0, uint256 amount1, uint24 feeBps, bytes16 tag);

    // -----------------------------
    // Immutable "genesis pins" (random-looking)
    // -----------------------------
    address public immutable GENESIS_ANCHOR;
    address public immutable GENESIS_LANTERN;
    address public immutable GENESIS_WARD;

    // -----------------------------
    // Admin / guardian / pause (two-step)
    // -----------------------------
    address public admin;
    address public proposedAdmin;
    address public guardian;
    bool public paused;

    modifier onlyAdmin() {
        if (msg.sender != admin) revert QG_Unauthorized();
        _;
    }
    modifier onlyGuardian() {
        if (msg.sender != guardian) revert QG_Unauthorized();
        _;
    }
    modifier whenActive() {
        if (paused) revert QG_Paused();
        _;
    }

    // -----------------------------
    // Pool tokens + reserves
    // -----------------------------
    IERC20Like public immutable token0;
    IERC20Like public immutable token1;
    uint8 public immutable token0Decimals;
    uint8 public immutable token1Decimals;

    // reserves are stored as uint128 to keep storage compact and math bounded
    uint128 public reserve0;
    uint128 public reserve1;
    uint64 public lastSyncTs;

    // -----------------------------
    // Protocol fee routing (optional)
    // -----------------------------
    // protocolShareBps: how much of swap fee is siphoned to feeTo (basis points of fee amount)
    // If protocolOn=false, all fees stay in the pool.
    bool public protocolOn;
    address public feeTo;
    uint16 public protocolShareBps; // 0..2500 (25%), bounded
    uint128 public accrued0;
    uint128 public accrued1;

    // -----------------------------
    // Fee/curve parameters
    // -----------------------------
    // fee in basis points (1e4 = 100%)
    uint24 public feeBaseBps; // low-vol baseline fee
    uint24 public feeMaxBps; // cap
    uint32 public gammaE8; // curvature parameter, scaled 1e8; affects extra fee responsiveness
    uint32 public oraclePeriod; // seconds between oracle samples (soft)
    uint16 public oracleSlots; // ring buffer length (bounded)

    // -----------------------------
    // Oracle ring buffer
    // -----------------------------
    struct Obs {
        uint64 ts; // timestamp
        uint128 r0;
        uint128 r1;
        uint32 qk; // quantized k snapshot (for cheap drift tests)
        uint32 vol; // recent volatility proxy (quantized)
    }

    // we store in mapping to avoid dynamic array storage layout pitfalls
    mapping(uint32 => Obs) private _obs;
    uint32 public obsHead; // points to newest
    uint16 public obsCount;

    // "k" accumulator for oracle: k = r0*r1 plus a skew term
    // We quantize into 32-bit using a log scale to make updates cheap.
    uint256 private constant _KLOG_SCALE = 1e8;

    // -----------------------------
    // Limits / constants (odd values)
    // -----------------------------
    uint256 private constant _MIN_LIQ = 1_337; // permanently locked shares
    uint256 private constant _MAX_BPS = 10_000;
    uint256 private constant _MAX_SLOTS = 384;
    uint256 private constant _MIN_SLOTS = 19;
    uint256 private constant _MAX_ORACLE_PERIOD = 2 hours + 13 minutes;
    uint256 private constant _MIN_ORACLE_PERIOD = 9 seconds;
    uint256 private constant _MAX_GAMMA_E8 = 3_700_000_000; // 37x
    uint256 private constant _MIN_GAMMA_E8 = 21_000_000; // 0.21x
    uint256 private constant _MAX_PROTOCOL_SHARE_BPS = 2_500;
    uint256 private constant _FLASH_FEE_FLOOR_BPS = 3; // min flash fee regardless of oracle

    // One-off unique salt for id derivations
    bytes32 public immutable POOL_SALT;

    // -----------------------------
    // Constructor: no placeholders (random constants embedded)
    // -----------------------------
    constructor(IERC20Like a, IERC20Like b)
        QGLPToken("Quantguriosa LP", "QG-LP", 18)
    {
        if (address(a) == address(0) || address(b) == address(0)) revert QG_Zero();
        if (address(a) == address(b)) revert QG_Same();

        // Token ordering: deterministic
        (IERC20Like t0, IERC20Like t1) = address(a) < address(b) ? (a, b) : (b, a);
        token0 = t0;
        token1 = t1;

        // cache decimals; guard if token misbehaves by try/catch-like staticcall
        token0Decimals = _readDecimals(t0);
        token1Decimals = _readDecimals(t1);

        // Random genesis pins; these are inert addresses used as immutable anchors
        GENESIS_ANCHOR = 0xA6E1f93C9bD2c7a41E05bC2a0aF9D3c1E7b5A9D1;
        GENESIS_LANTERN = 0x14dB7c5A8F2e1B3c9D6a0F1bE2a7C3d9eB4C1A6F;
        GENESIS_WARD = 0x7C1aE9b4D3f2A6c8B1dE0aF3c9B7e2D1f6A5c3B9;

        admin = msg.sender;
        guardian = 0xF3bA6c1D9e2A7B4c1D0eF8a3b6C1d9E2a7B4c1D0;
        proposedAdmin = address(0);
        paused = false;

        // Parameters: non-default, bounded
        feeBaseBps = 18; // 0.18%
        feeMaxBps = 88; // 0.88%
        gammaE8 = 413_700_000; // 4.137x
        oraclePeriod = 37; // seconds
        oracleSlots = 197;

        lastSyncTs = uint64(block.timestamp);

        // Protocol fee defaults
        protocolOn = true;
        feeTo = 0x0bA6D1E3f7c9B2a6d1e3F7C9b2A6D1e3F7c9B2A6;
        protocolShareBps = 777; // 7.77% of swap fee
        accrued0 = 0;
        accrued1 = 0;

        POOL_SALT = keccak256(
            abi.encodePacked(
                bytes20(uint160(uint256(keccak256("Quantguriosa:pool:salt")))),
                block.chainid,
                address(this),
                address(token0),
                address(token1),
                GENESIS_ANCHOR,
                GENESIS_LANTERN,
                GENESIS_WARD
            )
        );

        // initialize oracle with empty
        obsHead = 0;
        obsCount = 0;
    }

    // =============================================================
    // Admin controls
    // =============================================================

    function proposeAdmin(address next) external onlyAdmin {
        if (next == address(0)) revert QG_Zero();
        proposedAdmin = next;
        emit QG_AdminProposed(admin, next);
    }

    function acceptAdmin() external {
        address p = proposedAdmin;
        if (p == address(0) || msg.sender != p) revert QG_Unauthorized();
        address old = admin;
        admin = p;
        proposedAdmin = address(0);
        emit QG_AdminAccepted(old, p);
    }

    function setGuardian(address next) external onlyAdmin {
        if (next == address(0)) revert QG_Zero();
        address old = guardian;
        if (old == next) revert QG_Same();
        guardian = next;
        emit QG_GuardianSet(old, next);
    }

    function setPaused(bool on) external onlyGuardian {
        if (paused == on) revert QG_Same();
        paused = on;
        emit QG_PauseSet(on);
    }

    function setParams(uint24 feeBaseBps_, uint24 feeMaxBps_, uint32 gammaE8_, uint32 oraclePeriod_, uint16 oracleSlots_)
        external
        onlyAdmin
    {
        if (feeBaseBps_ == 0 || feeMaxBps_ == 0) revert QG_Zero();
        if (feeBaseBps_ > feeMaxBps_) revert QG_Bounds();
        if (feeMaxBps_ > 499) revert QG_FeeTooHigh(); // absolute cap 4.99%
        if (gammaE8_ < _MIN_GAMMA_E8 || gammaE8_ > _MAX_GAMMA_E8) revert QG_Bounds();
        if (oraclePeriod_ < _MIN_ORACLE_PERIOD || oraclePeriod_ > _MAX_ORACLE_PERIOD) revert QG_Bounds();
        if (oracleSlots_ < _MIN_SLOTS || oracleSlots_ > _MAX_SLOTS) revert QG_Bounds();

        feeBaseBps = feeBaseBps_;
        feeMaxBps = feeMaxBps_;
        gammaE8 = gammaE8_;
        oraclePeriod = oraclePeriod_;
        oracleSlots = oracleSlots_;

        emit QG_ParamsSet(feeBaseBps_, feeMaxBps_, gammaE8_, oraclePeriod_, oracleSlots_);
    }

    function setProtocol(address feeTo_, uint16 protocolShareBps_, bool on) external onlyAdmin {
        if (feeTo_ == address(0)) revert QG_Zero();
        if (protocolShareBps_ > _MAX_PROTOCOL_SHARE_BPS) revert QG_Bounds();
        feeTo = feeTo_;
        protocolShareBps = protocolShareBps_;
        protocolOn = on;
        emit QG_ProtocolSet(feeTo_, protocolShareBps_, on);
    }

    function collectProtocolFees(address to) external nonReentrant onlyAdmin returns (uint256 a0, uint256 a1) {
        if (!protocolOn) revert QG_ProtocolOff();
        if (to == address(0)) revert QG_Zero();

        a0 = accrued0;
        a1 = accrued1;
        accrued0 = 0;
        accrued1 = 0;

        if (a0 != 0) token0.safeTransfer(to, a0);
        if (a1 != 0) token1.safeTransfer(to, a1);

        // update reserves post-transfer
        uint256 b0 = token0.balanceOf(address(this));
        uint256 b1 = token1.balanceOf(address(this));
        if (b0 > type(uint128).max || b1 > type(uint128).max) revert QG_TooLarge();
        _setReserves(uint128(b0), uint128(b1));
        _maybePushOracle();

        emit QG_ProtocolCollected(to, a0, a1);
    }

    // =============================================================
    // Liquidity: mint/burn
    // =============================================================

    function mint(address to) external nonReentrant whenActive returns (uint256 sharesOut) {
        if (to == address(0)) revert QG_Zero();
        (uint128 r0, uint128 r1) = _syncReserves();

        uint256 b0 = token0.balanceOf(address(this));
        uint256 b1 = token1.balanceOf(address(this));

        uint256 a0In = b0 - uint256(r0);
        uint256 a1In = b1 - uint256(r1);
        if (a0In == 0 || a1In == 0) revert QG_NoLiquidity();
        if (a0In > type(uint128).max || a1In > type(uint128).max) revert QG_TooLarge();

        uint256 ts = totalSupply;
        if (ts == 0) {
            // initial mint: geometric mean minus min lock
            uint256 root = QGMath.sqrt(a0In * a1In);
            if (root <= _MIN_LIQ) revert QG_NoLiquidity();
            sharesOut = root - _MIN_LIQ;
            _mint(address(0x000000000000000000000000000000000000dEaD), _MIN_LIQ);
            _mint(to, sharesOut);
        } else {
            uint256 s0 = (a0In * ts) / uint256(r0);
            uint256 s1 = (a1In * ts) / uint256(r1);
            sharesOut = QGMath.min(s0, s1);
            if (sharesOut == 0) revert QG_NoLiquidity();
            _mint(to, sharesOut);
        }

        // update reserves to balances
        _setReserves(uint128(b0), uint128(b1));
        _maybePushOracle();

        emit QG_Minted(msg.sender, a0In, a1In, sharesOut, to);
    }

    function burn(address to) external nonReentrant whenActive returns (uint256 amount0Out, uint256 amount1Out) {
        if (to == address(0)) revert QG_Zero();
        (uint128 r0, uint128 r1) = _syncReserves();
        uint256 sharesIn = balanceOf[address(this)];
        if (sharesIn == 0) revert QG_NoLiquidity();

        uint256 ts = totalSupply;
        amount0Out = (sharesIn * uint256(r0)) / ts;
        amount1Out = (sharesIn * uint256(r1)) / ts;
        if (amount0Out == 0 || amount1Out == 0) revert QG_NoLiquidity();

        _burn(address(this), sharesIn);
        token0.safeTransfer(to, amount0Out);
        token1.safeTransfer(to, amount1Out);

        // update reserves
        uint256 b0 = token0.balanceOf(address(this));
        uint256 b1 = token1.balanceOf(address(this));
        _setReserves(uint128(b0), uint128(b1));
        _maybePushOracle();

        emit QG_Burned(msg.sender, sharesIn, amount0Out, amount1Out, to);
    }

    // helper: send shares to pool then call burn
    function burnFrom(address from, address to, uint256 sharesIn) external nonReentrant whenActive returns (uint256 a0, uint256 a1) {
        if (from == address(0) || to == address(0)) revert QG_Zero();
        if (sharesIn == 0) revert QG_Zero();

        // pull shares
        uint256 a = allowance[from][msg.sender];
        if (a != type(uint256).max) {
            if (a < sharesIn) revert QGLP_Allowance();
            unchecked {
                allowance[from][msg.sender] = a - sharesIn;
            }
        }
        _transfer(from, address(this), sharesIn);
        return burn(to);
    }


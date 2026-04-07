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

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


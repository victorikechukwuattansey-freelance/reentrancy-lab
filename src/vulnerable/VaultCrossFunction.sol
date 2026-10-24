// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VaultCrossFunction
/// @notice Deliberately vulnerable. Local reentrancy guard on `withdraw` but
///         NOT on `transfer`. Both functions touch `balances`. A recipient
///         that re-enters via `transfer` during the `withdraw` callback
///         duplicates their claim before the withdraw completes.
/// @dev Do not use.
contract VaultCrossFunction {
    mapping(address => uint256) public balances;
    bool private _withdrawing;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        require(!_withdrawing, "reentrant");
        _withdrawing = true;

        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");

        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok, "send failed");

        balances[msg.sender] = 0;

        _withdrawing = false;
    }

    /// @notice NOT guarded by `_withdrawing`. This is the gap.
    function transfer(address to, uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    receive() external payable {}
}

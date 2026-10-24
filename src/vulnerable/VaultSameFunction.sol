// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VaultSameFunction
/// @notice Deliberately vulnerable. The balance is zeroed AFTER the external
///         call, so a recipient that re-enters `withdraw` during the callback
///         sees the pre-withdrawal balance and can drain the vault.
/// @dev Do not use. For educational testing only.
contract VaultSameFunction {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");

        // External call BEFORE state update — the vulnerable line.
        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok, "send failed");

        balances[msg.sender] = 0; // ← too late: callback already happened
    }

    receive() external payable {}
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @title VaultCEI
/// @notice Same external interface as VaultSameFunction, but state is updated
///         BEFORE the external call. A reentrant `withdraw` finds
///         balances[msg.sender] == 0 and reverts with "no balance".
contract VaultCEI {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");

        balances[msg.sender] = 0; // ← CHECK-EFFECT: zero the balance first

        (bool ok,) = msg.sender.call{value: bal}(""); // ← INTERACTION: then send
        require(ok, "send failed");
    }

    receive() external payable {}
}

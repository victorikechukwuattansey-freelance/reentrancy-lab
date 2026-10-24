// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/// @title VaultGlobalGuard
/// @notice Fix for cross-function reentrancy. Uses OZ's ReentrancyGuard on
///         every external function that reads or writes `balances`, so a
///         reentrant `transfer` from within `withdraw`'s callback reverts
///         with `ReentrancyGuardReentrantCall`.
contract VaultGlobalGuard is ReentrancyGuard {
    mapping(address => uint256) public balances;

    function deposit() external payable nonReentrant {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");

        balances[msg.sender] = 0; // CEI as well — defense in depth

        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok, "send failed");
    }

    function transfer(address to, uint256 amount) external nonReentrant {
        require(balances[msg.sender] >= amount, "insufficient");
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }

    receive() external payable {}
}

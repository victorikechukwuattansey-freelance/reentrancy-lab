// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VaultSameFunction} from "../src/vulnerable/VaultSameFunction.sol";
import {VaultCEI} from "../src/fixed/VaultCEI.sol";
import {SameFunctionAttacker} from "../src/attack/SameFunctionAttacker.sol";

contract SameFunctionTest is Test {
    VaultSameFunction internal vault;
    VaultCEI internal fixedVault;
    SameFunctionAttacker internal attacker;

    address internal victim1 = makeAddr("victim1");
    address internal victim2 = makeAddr("victim2");

    function setUp() public {
        vault = new VaultSameFunction();
        fixedVault = new VaultCEI();
        attacker = new SameFunctionAttacker(address(vault));

        // Seed vulnerable vault: victim1 = 10, victim2 = 5
        // Rule: deal → prank → deposit. Every deposit gets its own prank.
        vm.deal(victim1, 10 ether);
        vm.prank(victim1);
        vault.deposit{value: 10 ether}();

        vm.deal(victim2, 5 ether);
        vm.prank(victim2);
        vault.deposit{value: 5 ether}();

        // Seed fixed vault the same way. Re-deal because victims spent their balance.
        vm.deal(victim1, 10 ether);
        vm.prank(victim1);
        fixedVault.deposit{value: 10 ether}();

        vm.deal(victim2, 5 ether);
        vm.prank(victim2);
        fixedVault.deposit{value: 5 ether}();
    }

    // ─── Finding 1: exploit drains the vulnerable vault ────────────────

    function test_ExploitDrains() public {
        // Sanity: state seeded correctly
        assertEq(address(vault).balance, 15 ether, "vault funded");
        assertEq(vault.balances(victim1), 10 ether, "victim1 deposited");
        assertEq(vault.balances(victim2), 5 ether, "victim2 deposited");

        vm.deal(address(attacker), 1 ether);
        attacker.attack(1 ether);

        assertEq(address(vault).balance, 0, "vault drained");
        assertEq(address(attacker).balance, 16 ether, "attacker holds 1 + 15");
        assertGt(attacker.reentryCount(), 0, "reentry occurred");
    }

    // ─── Finding 1: CEI fix blocks the exploit ─────────────────────────

    function test_FixedBlocksExploit() public {
        assertEq(address(fixedVault).balance, 15 ether, "fixed vault funded");
        assertEq(fixedVault.balances(victim1), 10 ether);
        assertEq(fixedVault.balances(victim2), 5 ether);

        SameFunctionAttacker fixedAttacker = new SameFunctionAttacker(address(fixedVault));
        vm.deal(address(fixedAttacker), 1 ether);

        // CEI zeroes the balance before the callback → reentrant withdraw reverts
        vm.expectRevert();
        fixedAttacker.attack(1 ether);

        // Vault untouched; all victim claims intact
        assertEq(address(fixedVault).balance, 15 ether, "fixed vault not drained");
        assertEq(fixedVault.balances(victim1), 10 ether);
        assertEq(fixedVault.balances(victim2), 5 ether);
    }

    // ─── Finding 1: fix preserves normal operation ─────────────────────

    function test_NormalOperationStillWorks() public {
        // victim1 starts with 0 balance after setUp (dealt 10, deposited 10)
        assertEq(victim1.balance, 0);

        vm.prank(victim1);
        fixedVault.withdraw();

        assertEq(fixedVault.balances(victim1), 0, "victim1 balance zeroed");
        assertEq(victim1.balance, 10 ether, "victim1 received funds");
        assertEq(address(fixedVault).balance, 5 ether, "victim2's deposit untouched");
    }
}

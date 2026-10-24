// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {VaultCrossFunction} from "../src/vulnerable/VaultCrossFunction.sol";
import {CrossFunctionAttacker} from "../src/attack/CrossFunctionAttacker.sol";
import {VaultGlobalGuard} from "../src/fixed/VaultGlobalGuard.sol";

contract CrossFunctionTest is Test {
    VaultCrossFunction internal vault;
    CrossFunctionAttacker internal attacker;

    address internal victim = makeAddr("victim");
    address internal accomplice = makeAddr("accomplice");

    function setUp() public {
        vault = new VaultCrossFunction();
        attacker = new CrossFunctionAttacker(address(vault), accomplice);

        // Victim seeds the vault with 10 ETH — this is what will be stolen
        vm.deal(victim, 10 ether);
        vm.prank(victim);
        vault.deposit{value: 10 ether}();
    }

    function test_ExploitDuplicatesClaim() public {
        vm.deal(address(attacker), 1 ether);

        // Before attack: vault has only the victim's 10 ETH
        assertEq(address(vault).balance, 10 ether, "vault has victim deposit");

        // Attacker deposits 1 ETH and attacks in the same call
        attacker.attack(1 ether);

        // After attack: vault holds 10 ETH, but claims total 11 → insolvent
        assertEq(address(vault).balance, 10 ether, "vault drained by 1 ETH");
        assertEq(address(attacker).balance, 1 ether, "attacker got 1 ETH cash");
        assertEq(vault.balances(accomplice), 1 ether, "accomplice has 1 ETH claim");
        assertEq(vault.balances(address(attacker)), 0, "attacker claim zeroed");
        assertEq(vault.balances(victim) + vault.balances(accomplice), 11 ether, "claims exceed balance");

        // Proof of insolvency: accomplice exits, victim cannot
        vm.prank(accomplice);
        vault.withdraw();
        assertEq(accomplice.balance, 1 ether);

        vm.prank(victim);
        vm.expectRevert("send failed");
        vault.withdraw();
    }

    function test_FixedBlocksCrossFunctionExploit() public {
        VaultGlobalGuard fixedVault = new VaultGlobalGuard();
        CrossFunctionAttacker fixedAttacker = new CrossFunctionAttacker(address(fixedVault), accomplice);

        // Victim seeds the fixed vault
        vm.deal(victim, 10 ether);
        vm.prank(victim);
        fixedVault.deposit{value: 10 ether}();

        // Attacker tries the same exploit
        vm.deal(address(fixedAttacker), 1 ether);

        // The reentrant transfer reverts with ReentrancyGuardReentrantCall,
        // the outer withdraw fails, the whole attack unwinds
        vm.expectRevert();
        fixedAttacker.attack(1 ether);

        // Vault unchanged
        assertEq(address(fixedVault).balance, 10 ether, "vault intact");
        assertEq(fixedVault.balances(victim), 10 ether);
        assertEq(fixedVault.balances(accomplice), 0, "no dup claim");
    }

    function test_FixedNormalOperationStillWorks() public {
        VaultGlobalGuard fixedVault = new VaultGlobalGuard();

        vm.deal(victim, 10 ether);
        vm.prank(victim);
        fixedVault.deposit{value: 10 ether}();

        // transfer still works
        vm.prank(victim);
        fixedVault.transfer(accomplice, 3 ether);

        assertEq(fixedVault.balances(victim), 7 ether);
        assertEq(fixedVault.balances(accomplice), 3 ether);

        // withdraw still works
        vm.prank(accomplice);
        fixedVault.withdraw();
        assertEq(accomplice.balance, 3 ether);
    }
}

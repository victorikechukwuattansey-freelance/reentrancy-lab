// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ILendingView} from "../vulnerable/LendingReadOnly.sol";
import {Keeper} from "./Keeper.sol";

/// @notice A borrower that self-reports to the keeper on every ETH receive.
///         Models the "monitored user" pattern where integrators subscribe
///         to state changes. The bug is that the report fires while the borrow
///         is mid-transition — before the compensating deposit runs.
contract Borrower {
    ILendingView public immutable lending;
    Keeper public immutable keeper;

    constructor(address _lending, address _keeper) {
        lending = ILendingView(_lending);
        keeper = Keeper(_keeper);
    }

    /// @notice Deposit ETH into the lending contract. The amount is msg.value.
    function deposit() external payable {
        lending.deposit{value: msg.value}();
    }

    function borrow(uint256 amount) external {
        lending.borrow(amount);
    }

    receive() external payable {
        keeper.checkAndLiquidate(address(this)); // read happens mid-transition
        lending.deposit{value: msg.value}(); // compensating deposit
    }
}

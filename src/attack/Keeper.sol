// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ILendingView} from "../vulnerable/LendingReadOnly.sol";

/// @notice Mock integrator. Models a keeper bot or a protocol that reads
///         `healthFactor()` as an oracle and liquidates when it drops below
///         threshold. It has no state and writes nothing — the attack is
///         purely a read of a view function at the wrong moment.
contract Keeper {
    ILendingView public immutable lending;

    constructor(address _lending) {
        lending = ILendingView(_lending);
    }

    function checkAndLiquidate(address user) external {
        if (lending.healthFactor(user) < lending.THRESHOLD()) {
            lending.liquidate(user);
        }
    }
}

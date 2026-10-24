// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";
import {ILendingView} from "../vulnerable/LendingReadOnly.sol";

/// @notice Fix for read-only reentrancy. `liquidate` is guarded by
///         `nonReentrant`, so any attempt to liquidate during `borrow`'s
///         callback reverts with ReentrancyGuardReentrantCall. The mid-state
///         during the callback is no longer reachable by a mutating integrator.
contract LendingGuard is ReentrancyGuard, ILendingView {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    uint256 public constant override THRESHOLD = 1.2e18;

    function deposit() external payable override {
        collateral[msg.sender] += msg.value;
    }

    function borrow(uint256 amount) external override nonReentrant {
        require(healthFactor(msg.sender) >= 1e18, "unhealthy pre-borrow");
        debt[msg.sender] += amount;
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "borrow failed");
    }

    function healthFactor(address user) public view override returns (uint256) {
        if (debt[user] == 0) return type(uint256).max;
        return (collateral[user] * 1e18) / debt[user];
    }

    function liquidate(address user) external override nonReentrant {
        require(healthFactor(user) < THRESHOLD, "healthy");
        uint256 seized = collateral[user];
        collateral[user] = 0;
        debt[user] = 0;
        collateral[msg.sender] += seized;
    }

    receive() external payable {}
}

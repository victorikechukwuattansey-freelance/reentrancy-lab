// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ILendingView {
    function deposit() external payable;
    function borrow(uint256 amount) external;
    function healthFactor(address user) external view returns (uint256);
    function liquidate(address user) external;
    function THRESHOLD() external view returns (uint256);
}

/// @title LendingReadOnly
/// @notice Deliberately vulnerable. `healthFactor` is a public view function
///         that an integrator (keeper, oracle, another protocol) may call at
///         any time. During `borrow`'s callback, `debt` has been updated but
///         the borrower's compensating deposit hasn't run yet — so a keeper
///         that reads `healthFactor` mid-callback sees an unhealthy position
///         and liquidates. No state is written by the attacker; the view is
///         the attack surface.
/// @dev Do not use.
contract LendingReadOnly is ILendingView {
    mapping(address => uint256) public collateral;
    mapping(address => uint256) public debt;

    uint256 public constant override THRESHOLD = 1.2e18;

    function deposit() external payable override {
        collateral[msg.sender] += msg.value;
    }

    function borrow(uint256 amount) external override {
        require(healthFactor(msg.sender) >= 1e18, "unhealthy pre-borrow");
        debt[msg.sender] += amount;

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "borrow failed");
    }

    function healthFactor(address user) public view override returns (uint256) {
        if (debt[user] == 0) return type(uint256).max;
        return (collateral[user] * 1e18) / debt[user];
    }

    function liquidate(address user) external override {
        require(healthFactor(user) < THRESHOLD, "healthy");
        uint256 seized = collateral[user];
        collateral[user] = 0;
        debt[user] = 0;
        collateral[msg.sender] += seized;
    }

    receive() external payable {}
}

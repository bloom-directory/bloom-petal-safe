// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

contract FixtureToken {
    mapping(address => uint256) public balanceOf;

    constructor() {
        balanceOf[msg.sender] = 1_000_000;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.26;

import "@openzeppelin/contracts/token/ERC20/IERC20.sol";
import "@openzeppelin/contracts/token/ERC20/utils/SafeERC20.sol";
import "./Interface/IERC20Permit.sol";

contract TokenBank {
    using SafeERC20 for IERC20;

    // user -> token -> balances
    mapping(address => mapping(address => uint256)) public balances;

    event Deposit(address indexed user, address indexed token, uint256 amount);
    event Withdraw(address indexed user, address indexed token, uint256 amount);

    /**
     * @dev 基于 Permit 签名的存款函数
     * @param token 代币地址（需实现 IERC20Permit）
     * @param amount 存款金额
     * @param deadline 签名过期时间
     * @param v 签名参数v
     * @param r 签名参数r
     * @param s 签名参数s
     */
    function permitDeposit(
        address token,
        uint256 amount,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // 1. 参数校验
        require(token != address(0), "Invalid token address");
        require(amount > 0, "Amount must be greater than 0");

        // 2. 调用 Permit 完成授权：将 msg.sender 的代币授权给 TokenBank（spender = address(this)）
        IERC20Permit(token).permit(
            msg.sender,    // owner：存款用户（签名者）
            address(this), // spender：TokenBank 合约（需要授权才能转走代币）
            amount,        // value：授权金额 = 存款金额
            deadline,      // 签名过期时间
            v,             // 签名参数v
            r,             // 签名参数r
            s              // 签名参数s
        );

        // 3. 执行存款逻辑（和 deposit 函数一致）
        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        balances[msg.sender][token] += amount;
        emit Deposit(msg.sender, token, amount);
    }

    /**
     * @dev 用户需要先调用代币合约的 approve() 授权
     */
    function deposit(address token, uint256 amount) external {
        require(token != address(0), "Invalid token address");
        require(amount > 0, "Amount must be greater than 0");

        IERC20(token).safeTransferFrom(msg.sender, address(this), amount);
        balances[msg.sender][token] += amount;
        emit Deposit(msg.sender, token, amount);
    }

    function withdraw(address token, uint256 amount) external {
        require(token != address(0), "Invalid token address");
        require(amount > 0, "Amount must be greater than 0");
        require(balances[msg.sender][token] >= amount, "Insufficient balance");

        balances[msg.sender][token] -= amount;

        IERC20(token).safeTransfer(msg.sender, amount);

        emit Withdraw(msg.sender, token, amount);
    }

    function getBalance(
        address user,
        address token
    ) external view returns (uint256) {
        return balances[user][token];
    }

    function getBalances(
        address user,
        address[] calldata tokens        
    ) external view returns (uint256[] memory) {
        uint256[] memory userBalances = new uint256[](tokens.length);

        for (uint256 i = 0; i < tokens.length; i++) {
            userBalances[i] = balances[user][tokens[i]];
        }

        return userBalances;
    }
}

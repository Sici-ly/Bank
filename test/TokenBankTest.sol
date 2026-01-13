// SPDX-License-Identifier: MIT
pragma solidity ^0.8.18;

// Foundry 标准测试基类，提供 assert、vm cheatcode 等能力
import {Test} from "forge-std/Test.sol";

// 被测试的合约
import {TokenBank} from "../src/3_TokenBank.sol";

// 支持 permit 的 ERC20 Mock
import {ERC20Mock} from "./mocks/ERC20Mock.sol";

contract TokenBankTest is Test {
    // ===== 被测试合约实例 =====
    TokenBank public tokenBank;
    ERC20Mock public token;

    // ===== 测试用户信息 =====
    // Foundry 允许直接使用私钥，并通过 vm.addr 映射成地址
    uint256 userPrivateKey = 0xA11CE;
    address user;

    // ===== 测试参数 =====
    uint256 depositAmount = 100;
    uint256 deadline;

    /**
     * @dev setUp 会在「每一个测试函数执行前」被自动调用
     *      用于初始化运行期状态，保证测试相互独立
     */
    function setUp() public {
        // 由私钥推导出用户地址（用于签名校验）
        user = vm.addr(userPrivateKey);

        // 设置签名有效期（基于当前区块时间）
        deadline = block.timestamp + 1 hours;

        // 部署支持 permit 的 ERC20 Mock
        token = new ERC20Mock(
            "MockToken",
            "MTK",
            address(this), // 初始代币给测试合约本身
            1 * 10**6
        );

        // 部署 TokenBank（无 constructor 参数）
        tokenBank = new TokenBank();

        // 给 user 铸造代币，确保其有足够余额存款
        token.mint(user, 1 * 10**2);
    }

    /*//////////////////////////////////////////////////////////////
                            工具函数
    //////////////////////////////////////////////////////////////*/

    /**
     * @dev 构造 EIP-2612 Permit 所需的离线签名
     *      该函数仅用于测试，真实业务中签名应在链下完成
     *
     * @param owner      代币持有者（签名者）
     * @param spender    被授权的合约（TokenBank）
     * @param value      授权金额
     * @param nonce      当前 nonce（防重放）
     * @param deadline   签名过期时间
     * @param privateKey owner 对应的私钥（Foundry 测试专用）
     */
    function _signPermit(
        address owner,
        address spender,
        uint256 value,
        uint256 nonce,
        uint256 deadline,
        uint256 privateKey
    ) internal view returns (uint8 v, bytes32 r, bytes32 s) {
        // Permit 结构体类型哈希（EIP-2612 固定格式）
        bytes32 permitTypeHash = keccak256(
            "Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)"
        );

        // 对 Permit 结构体进行 abi.encode + keccak256
        bytes32 structHash = keccak256(
            abi.encode(
                permitTypeHash,
                owner,
                spender,
                value,
                nonce,
                deadline
            )
        );

        // 构造最终的 EIP-712 digest
        bytes32 digest = keccak256(
            abi.encodePacked(
                "\x19\x01",
                token.DOMAIN_SEPARATOR(),
                structHash
            )
        );

        // 使用 Foundry 提供的 vm.sign 生成 v/r/s
        return vm.sign(privateKey, digest);
    }

    /*//////////////////////////////////////////////////////////////
                    1️. 正常签名 → 存款成功
    //////////////////////////////////////////////////////////////*/

    function testPermitDeposit_Success() public {
        // 获取当前 nonce（必须和签名时使用的一致）
        uint256 nonce = token.nonces(user);

        // 构造合法的 Permit 签名
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            user,
            address(tokenBank),
            depositAmount,
            nonce,
            deadline,
            userPrivateKey
        );

        // 模拟 user 调用 TokenBank（msg.sender = user）
        vm.prank(user);
        tokenBank.permitDeposit(
            address(token),
            depositAmount,
            deadline,
            v,
            r,
            s
        );

        // 断言 1：TokenBank 内部账本余额正确
        assertEq(
            tokenBank.getBalance(user, address(token)),
            depositAmount
        );

        // 断言 2：用户链上余额减少
        assertEq(
            token.balanceOf(user),
            100 - depositAmount
        );

        // 断言 3：nonce 被成功消费（防止重放攻击）
        assertEq(token.nonces(user), nonce + 1);
    }

    /*//////////////////////////////////////////////////////////////
                    2️. 签名过期 → 失败
    //////////////////////////////////////////////////////////////*/

    function testPermitDeposit_ExpiredSignature() public {
        // 构造一个已经过期的 deadline
        uint256 expiredDeadline = block.timestamp - 1;
        uint256 nonce = token.nonces(user);

        // 使用过期 deadline 生成签名
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            user,
            address(tokenBank),
            depositAmount,
            nonce,
            expiredDeadline,
            userPrivateKey
        );

        // 期望 ERC20Permit 在 permit 阶段直接 revert
        vm.expectRevert("ERC20Permit: expired deadline");
        vm.prank(user);
        tokenBank.permitDeposit(
            address(token),
            depositAmount,
            expiredDeadline,
            v,
            r,
            s
        );
    }

    /*//////////////////////////////////////////////////////////////
                    3️. 无效签名 → 失败
    //////////////////////////////////////////////////////////////*/

    function testPermitDeposit_InvalidSignature() public {
        uint256 nonce = token.nonces(user);

        // 使用错误的私钥签名（签名者 ≠ owner）
        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            user,
            address(tokenBank),
            depositAmount,
            nonce,
            deadline,
            0xBEEF // ❌ 非 user 的私钥
        );

        // 期望 permit 校验签名失败
        vm.expectRevert("ERC20Permit: invalid signature");
        vm.prank(user);
        tokenBank.permitDeposit(
            address(token),
            depositAmount,
            deadline,
            v,
            r,
            s
        );
    }

    /*//////////////////////////////////////////////////////////////
                重放攻击 → 失败（nonce 防重放）
    //////////////////////////////////////////////////////////////*/

    function testPermitDeposit_ReplayAttack() public {
        // ===== 第一次：正常签名并成功使用 =====
        uint256 nonce = token.nonces(user);

        (uint8 v, bytes32 r, bytes32 s) = _signPermit(
            user,
            address(tokenBank),
            depositAmount,
            nonce,
            deadline,
            userPrivateKey
        );

        // 第一次调用，应该成功
        vm.prank(user);
        tokenBank.permitDeposit(
            address(token),
            depositAmount,
            deadline,
            v,
            r,
            s
        );

        // 确认 nonce 已经被消费
        assertEq(token.nonces(user), nonce + 1);

        // ===== 第二次：尝试重放同一份签名 =====
        // 不重新签名，仍然使用旧的 v / r / s

        vm.expectRevert("ERC20Permit: invalid signature");
        vm.prank(user);
        tokenBank.permitDeposit(
            address(token),
            depositAmount,
            deadline,
            v,
            r,
            s
        );
    }

}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DevOpsTools} from "lib/foundry-devops/src/DevOpsTools.sol";
import {NearX, TransactionOrReceiptId} from "../src/NearX.sol";

contract Verify is Script {
    function run() external {
        address proxyAddress = DevOpsTools.get_most_recent_deployment(
            "ERC1967Proxy",
            block.chainid
        );
        TransactionOrReceiptId[] memory ids = new TransactionOrReceiptId[](2);

        ids[0].isTransaction = true;
        bytes32 txId = hex"2c53bcfe871da28decc45c3437f5864568d91af6d990dbc2662f11ce44c18d79";
        ids[0].id = txId;
        bytes
            memory txAccount = hex"7a61766f64696c2e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c";
        ids[0].account = txAccount;

        ids[1].isTransaction = false;
        bytes32 rxId = hex"7ff581f8517ec58459099a5af2465d5232fdcdd7c4da9c3d42a887bf6bd5457e";
        ids[1].id = rxId;
        bytes
            memory rxAccount = hex"70726963656f7261636c652e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c";
        ids[1].account = rxAccount;

        vm.startBroadcast();

        NearX lightClient = NearX(payable(proxyAddress));

        lightClient.requestVerify(ids);

        vm.stopBroadcast();
    }
}

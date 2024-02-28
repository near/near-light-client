// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DevOpsTools} from "lib/foundry-devops/src/DevOpsTools.sol";
import {NearX, decodePackedIds, TransactionOrReceiptId} from "../src/NearX.sol";

// TODO: refactor for 128, taking the input fixture
contract RequestSync is Script {
    function run() external {
        address mostRecentlyDeployedProxy = DevOpsTools
            .get_most_recent_deployment("ERC1967Proxy", block.chainid);

        vm.startBroadcast();

        NearX proxy = NearX(payable(mostRecentlyDeployedProxy));
        proxy.requestSync();

        vm.stopBroadcast();
    }
}

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import {Script} from "forge-std/Script.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {DevOpsTools} from "lib/foundry-devops/src/DevOpsTools.sol";
import {NearX} from "../src/NearX.sol";

contract Upgrade is Script {
    function run() external returns (address) {
        address mostRecentlyDeployedProxy = DevOpsTools
            .get_most_recent_deployment("ERC1967Proxy", block.chainid);

        vm.startBroadcast();
        NearX newAddress = new NearX();

        NearX proxy = NearX(payable(mostRecentlyDeployedProxy));
        proxy.upgradeToAndCall(address(newAddress), "");

        vm.stopBroadcast();
        return address(proxy);
    }
}

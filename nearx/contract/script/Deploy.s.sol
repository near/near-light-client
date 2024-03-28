// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/console.sol";
import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {NearX} from "../src/NearX.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Script} from "forge-std/Script.sol";
import {DevOpsTools} from "lib/foundry-devops/src/DevOpsTools.sol";

contract Deploy is Script {
    function setUp() public {}

    function run() external returns (address) {
        console.log(
            "Deploying NearX contract on chain %s",
            Strings.toString(block.chainid)
        );

        vm.startBroadcast();
        NearX lightClient = new NearX();
        ERC1967Proxy proxy = new ERC1967Proxy(address(lightClient), "");

        NearX(payable(proxy)).initialize(msg.sender);

        vm.stopBroadcast();
        return address(proxy);
    }
}

// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {NearX} from "../src/NearX.sol";
import {Script} from "forge-std/Script.sol";

contract Deploy is Script {
    function setUp() public {}

    function run() external returns (address) {
        address proxy = deployNearX();
        return proxy;
    }

    function deployNearX() public returns (address) {
        vm.startBroadcast();

        NearX lightClient = new NearX();

        ERC1967Proxy proxy = new ERC1967Proxy(address(lightClient), "");

        lightClient.initialize();

        vm.stopBroadcast();
        return address(proxy);
    }
}

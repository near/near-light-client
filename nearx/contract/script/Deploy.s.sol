// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.20;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {NearX} from "../src/NearX.sol";
import {Script} from "forge-std/Script.sol";

contract Deploy is Script {
    function setUp() public {}

    function run() external returns (address) {
        vm.startBroadcast();

        address proxy = deployNearX();
        init(proxy);

        vm.stopBroadcast();
        return proxy;
    }

    function deployNearX() public returns (address) {
        NearX lightClient = new NearX();

        ERC1967Proxy proxy = new ERC1967Proxy(address(lightClient), "");

        return address(proxy);
    }

    function init(address proxy) public {
        NearX client = NearX(payable(proxy));
        client.initialize();
    }
}

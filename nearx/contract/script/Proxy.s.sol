// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.19;
//
// import "forge-std/console.sol";
// import {NearX} from "../src/NearX.sol";
// import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
// import {Script} from "forge-std/Script.sol";
// import {Upgrades} from "@openzeppelin-foundry-upgrades/Upgrades.sol";
//
// contract Deploy3 is Script {
//     function setUp() public {}
//
//     function run() external returns (address) {
//         console.log(
//             "Deploying NearX contract on chain %s",
//             Strings.toString(block.chainid)
//         );
//         vm.startBroadcast();
//
//         // address proxy = Upgrades.deployUUPSProxy(
//         //     "NearX.sol",
//         //     abi.encodeCall(NearX.initialize, ())
//         // );
//
//         // NearX lightClient = new NearX{salt: CREATE2_SALT}();
//         // ERC1967Proxy proxy = new ERC1967Proxy(address(lightClient), "");
//         //
//         // NearX(payable(proxy)).initialize();
//
//         vm.stopBroadcast();
//         return address(proxy);
//     }
// }

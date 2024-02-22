// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.19;

import {ERC1967Proxy} from "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol";
import {NearX} from "../src/NearX.sol";
import {Script} from "forge-std/Script.sol";
import {DevOpsTools} from "lib/foundry-devops/src/DevOpsTools.sol";

// TODO: scripts need to support multiple envs
contract Initialise is Script {
    function setUp() public {}

    function run() external {
        address proxyAddress = DevOpsTools.get_most_recent_deployment(
            "ERC1967Proxy",
            block.chainid
        );
        vm.startBroadcast();
        NearX lightClient = NearX(payable(proxyAddress));

        // Succinct's goerli gateway
        address initialGateway = vm.envAddress("GATEWAY_ID");
        lightClient.updateGateway(initialGateway);

        bytes32 syncFunctionId = vm.envBytes32("SYNC_FUNCTION_ID");
        lightClient.updateSyncId(syncFunctionId);

        bytes32 verifyFunctionId = vm.envBytes32("VERIFY_FUNCTION_ID");
        lightClient.updateVerifyId(verifyFunctionId);

        bytes32 header = vm.envBytes32("NEAR_CHECKPOINT_HEADER_HASH");
        lightClient.setCheckpointHeader(header);

        vm.stopBroadcast();
    }
}

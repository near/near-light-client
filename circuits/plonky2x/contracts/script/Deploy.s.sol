// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Script.sol";
import {NearX} from "../src/NearX.sol";

contract DeployScript is Script {
    function setUp() public {}

    function run() public {
        vm.startBroadcast();

        address gateway = 0x6e4f1e9eA315EBFd69d18C2DB974EEf6105FB803;

        // Use the below to interact with an already deployed ZK light client.
        NearX lightClient = new NearX(gateway);

        bytes32 syncFunctionId = vm.envBytes32("SYNC_FUNCTION_ID");
        lightClient.updateSyncId(verifyFunctionId);

        bytes32 verifyFunctionId = vm.envBytes32("VERIFY_FUNCTION_ID");
        lightClient.updateVerifyId(verifyFunctionId);

        uint64 height = uint64(vm.envUint("GENESIS_HEIGHT"));
        bytes32 header = vm.envBytes32("GENESIS_HEADER");
        lightClient.setGenesisHeader(header);
    }
}

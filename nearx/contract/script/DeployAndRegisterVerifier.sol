// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Script.sol";
import "forge-std/Vm.sol";
import "forge-std/console.sol";
import {ISuccinctGateway} from "../../src/SuccinctGateway.sol";
import {FunctionVerifier} from "./FunctionVerifier.sol";

contract DeployAndRegisterFunction is Script {
    function run() external returns (bytes32, address) {
        vm.startBroadcast();

        bytes memory bytecode = type(FunctionVerifier).creationCode;

        address GATEWAY = vm.envAddress("GATEWAY_ID");
        console.logAddress(GATEWAY);

        bytes32 SALT = vm.envBytes32("CREATE2_SALT");

        address OWNER = msg.sender;

        (bytes32 functionId, address verifier) = SuccinctGateway(GATEWAY)
            .deployAndRegisterFunction(OWNER, bytecode, SALT);

        return (functionId, verifier);
    }
}

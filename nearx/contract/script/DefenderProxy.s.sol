// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "forge-std/console.sol";
import {NearX} from "../src/NearX.sol";
import {Strings} from "@openzeppelin/contracts/utils/Strings.sol";
import {Script} from "forge-std/Script.sol";
import {Defender, Options, ApprovalProcessResponse} from "openzeppelin-foundry-upgrades/Defender.sol";
import {Upgrades} from "@openzeppelin-foundry-upgrades/Upgrades.sol";

contract DefenderDeploy is Script {
    function setUp() public {}

    function run() external returns (address) {
        console.log(
            "Deploying NearX contract on chain %s",
            Strings.toString(block.chainid)
        );
        vm.startBroadcast();

        ApprovalProcessResponse memory upgradeApprovalProcess = Defender
            .getUpgradeApprovalProcess();

        if (upgradeApprovalProcess.via == address(0)) {
            revert(
                string.concat(
                    "Upgrade approval process with id ",
                    upgradeApprovalProcess.approvalProcessId,
                    " has no assigned address"
                )
            );
        }

        Options memory opts;
        opts.defender.useDefenderDeploy = true;

        address proxy = Upgrades.deployUUPSProxy(
            "NearX.sol",
            abi.encodeCall(NearX.initialize, (upgradeApprovalProcess.via)),
            opts
        );
        // NearX lightClient = new NearX{salt: CREATE2_SALT}();

        // ERC1967Proxy proxy = new ERC1967Proxy(address(lightClient), "");
        //
        // NearX(payable(proxy)).initialize();

        vm.stopBroadcast();
        return address(proxy);
        console.log("Deployed proxy to address", proxy);
    }
}

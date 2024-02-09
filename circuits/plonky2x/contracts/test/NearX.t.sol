// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/NearX.sol";

contract NearXTest is Test {
    NearX public lightClient;

    function setUp() public {
        lightClient = new NearX(address(0));
    }

    function testGetEncodePackedSync() public view {
        // TODO:
        bytes32 header = hex"63b87190ffbaa36d7dab50f918fe36f70ab26910a0e9d797161e2356561598e3";
        bytes memory encodedInput = abi.encodePacked(header);
        console.logBytes(encodedInput);
    }

    function testGetEncodePackedVerify() public view {
        // TODO:
        bytes32 header = hex"63b87190ffbaa36d7dab50f918fe36f70ab26910a0e9d797161e2356561598e3";

        bytes memory encodedInput = abi.encodePacked(header);
        console.logBytes(encodedInput);
    }
}

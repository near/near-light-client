// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/NearX.sol";

contract NearXTest is Test {
    NearX public lightClient;

    function setUp() public {
        lightClient = new NearX();
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
        bytes tx = hex"012c53bcfe871da28decc45c3437f5864568d91af6d990dbc2662f11ce44c18d797a61766f64696c2e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c";
        bytes rx = hex"007ff581f8517ec58459099a5af2465d5232fdcdd7c4da9c3d42a887bf6bd5457e70726963656f7261636c652e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c";

        TransactionOrReceiptId[] memory ids = new TransactionOrReceiptId[](2);
        ids[0].isTransaction = true;
        ids[0]
            .id = hex"63b87190ffbaa36d7dab50f918fe36f70ab26910a0e9d797161e2356561598e3";
        ids[1].isTransaction = false;
        ids[1]
            .id = hex"63b87190ffbaa36d7dab50f918fe36f70ab26910a0e9d797161e2356561598e3";
        ids[1]
            .account = hex"0000000000000000000000000000000000000000000000000000000000000000";
        bytes memory encodedInput = abi.encodePacked(
            latestHeader,
            encodePackedIds(ids)
        );

        console.logBytes(encodedInput);
    }
}

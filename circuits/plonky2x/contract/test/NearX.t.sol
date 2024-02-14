// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "../src/NearX.sol";
import {Bytes} from "../src/interfaces/Bytes.sol";

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

    function testGetEncodePackedVerify() public {
        // TODO:
        bytes32 header = hex"63b87190ffbaa36d7dab50f918fe36f70ab26910a0e9d797161e2356561598e3";
        bytes memory txIsAccount = hex"01";
        bytes32 txId = hex"2c53bcfe871da28decc45c3437f5864568d91af6d990dbc2662f11ce44c18d79";
        bytes
            memory txAccount = hex"7a61766f64696c2e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c";

        bytes memory rxIsAccount = hex"00";
        bytes32 rxId = hex"7ff581f8517ec58459099a5af2465d5232fdcdd7c4da9c3d42a887bf6bd5457e";
        bytes
            memory rxAccount = hex"70726963656f7261636c652e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c";

        TransactionOrReceiptId[] memory ids = new TransactionOrReceiptId[](2);

        ids[0].isTransaction = true;
        ids[0].id = txId;
        ids[0].account = txAccount;

        ids[1].isTransaction = false;
        ids[1].id = rxId;
        ids[1].account = rxAccount;

        bytes memory encodedIds = encodePackedIds(ids);
        bytes memory encodedInput = abi.encodePacked(header, encodedIds);

        bytes
            memory expected = hex"63b87190ffbaa36d7dab50f918fe36f70ab26910a0e9d797161e2356561598e3012c53bcfe871da28decc45c3437f5864568d91af6d990dbc2662f11ce44c18d797a61766f64696c2e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c007ff581f8517ec58459099a5af2465d5232fdcdd7c4da9c3d42a887bf6bd5457e70726963656f7261636c652e746573746e65742c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c2c";

        assertEq(encodedInput, expected);

        bytes32 encodedHeader = bytes32(encodedInput);
        assertEq(header, encodedHeader);

        TransactionOrReceiptId[] memory decodedIds = decodePackedIds(
            encodedIds
        );
        assertEq(ids[0].isTransaction, decodedIds[0].isTransaction);
        assertEq(ids[0].id, decodedIds[0].id);
        assertEq(ids[0].account, decodedIds[0].account);
        assertEq(ids[1].isTransaction, decodedIds[1].isTransaction);
        assertEq(ids[1].id, decodedIds[1].id);
        assertEq(ids[1].account, decodedIds[1].account);
    }

    function testDecodeResult() public {
        bytes
            memory inputData = hex"7ff581f8517ec58459099a5af2465d5232fdcdd7c4da9c3d42a887bf6bd5457e012c53bcfe871da28decc45c3437f5864568d91af6d990dbc2662f11ce44c18d7901";
        ProofVerificationResult[] memory results = decodePackedResults(
            inputData
        );
        bytes
            memory outputTest = hex"2c53bcfe871da28decc45c3437f5864568d91af6d990dbc2662f11ce44c18d79017ff581f8517ec58459099a5af2465d5232fdcdd7c4da9c3d42a887bf6bd5457e01";
        ProofVerificationResult[] memory expected = decodePackedResults(
            outputTest
        );
    }
}

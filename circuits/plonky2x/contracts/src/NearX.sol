// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {ISuccinctGateway} from "./interfaces/ISuccinctGateway.sol";
import {INearX, TransactionOrReceiptId} from "./interfaces/INearX.sol";

/// @notice The NearX contract is a light client for Near.
/// @dev
contract NearX is INearX {
    /// TODO: integrate this in a nice way
    uint64 public constant NETWORK = 1;

    /// @notice The address of the gateway contract.
    address public gateway;

    /// @notice The latest header that has been committed.
    bytes32 public latestHeader;

    /// @notice Sync function id.
    bytes32 public syncFunctionId;

    /// @notice Verify function id.
    bytes32 public verifyFunctionId;

    /// @notice Initialize the contract with the address of the gateway contract.
    constructor(address _gateway) {
        gateway = _gateway;
    }

    /// @notice Update the address of the gateway contract.
    function updateGateway(address _gateway) external {
        gateway = _gateway;
    }

    /// @notice Update the function ID for header range.
    function updateSyncId(bytes32 _functionId) external {
        syncFunctionId = _functionId;
    }

    /// @notice Update the function ID for next header.
    function updateVerifyId(bytes32 _functionId) external {
        verifyFunctionId = _functionId;
    }

    /// Note: Only for testnet. The genesis header should be set when initializing the contract.
    function setGenesisHeader(bytes32 _header) external {
        latestHeader = _header;
    }

    function ensureInitialized() internal {
        if (latestHeader == bytes32(0)) {
            revert HeaderNotInitialised();
        }
    }

    /// @notice Inputs of a sync request.
    function requestSync() external payable {
        ensureInitialized();

        ISuccinctGateway(gateway).requestCall{value: msg.value}(
            syncFunctionId,
            abi.encodePacked(latestHeader),
            address(this),
            abi.encodeWithSelector(this.sync.selector, latestHeader),
            500000
        );

        emit SyncRequested(latestHeader);
    }

    /// @notice Stores the new header for targetBlock.
    function sync() external {
        ensureInitialized();

        // Encode the circuit input.
        bytes memory input = abi.encodePacked(latestHeader);

        // Call gateway to get the proof result.
        bytes memory requestResult = ISuccinctGateway(gateway).verifiedCall(
            syncFunctionId,
            input
        );

        // Read the target header from request result.
        bytes32 targetHeader = abi.decode(requestResult, (bytes32));

        latestHeader = targetHeader;

        emit HeadUpdate(targetHeader);
    }

    function requestVerify(TransactionOrReceiptId[] memory ids)
        external
        payable
    {
        ensureInitialized();

        ISuccinctGateway(gateway).requestCall{value: msg.value}(
            verifyFunctionId,
            abi.encodePacked(latestHeader, encodePackedIds(ids)),
            address(this),
            abi.encodeWithSelector(this.verify.selector, latestHeader, ids),
            500000
        );
        emit VerifyRequested(latestHeader, ids);
    }

    function verify(TransactionOrReceiptId[] memory ids) external {
        ensureInitialized();

        bytes memory input = abi.encodePacked(
            latestHeader,
            encodePackedIds(ids)
        );

        // Call gateway to get the proof result.
        bytes memory requestResult = ISuccinctGateway(gateway).verifiedCall(
            verifyFunctionId,
            input
        );
        // TODO: emit event for the ids and their verification status
    }

    function encodePackedIds(TransactionOrReceiptId[] memory ids)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory output;
        for (uint256 i = 0; i < ids.length; i++) {
            output = abi.encodePacked(
                output,
                ids[i].isTransaction,
                ids[i].id,
                ids[i].account
            );
        }
        return output;
    }
}

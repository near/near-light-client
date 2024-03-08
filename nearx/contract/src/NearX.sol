// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import {ISuccinctGateway} from "./interfaces/ISuccinctGateway.sol";
import {INearX, TransactionOrReceiptId, ProofVerificationResult, encodePackedIds, decodePackedIds, decodePackedResults} from "./interfaces/INearX.sol";

/// @notice The NearX contract is a light client for Near.
contract NearX is INearX, Initializable, OwnableUpgradeable, UUPSUpgradeable {
    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() payable {
        _disableInitializers();
    }

    function initialize(address initialOwner) public initializer {
        __Ownable_init(initialOwner);
        __UUPSUpgradeable_init();
    }

    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyOwner
    {}

    uint32 public constant DEFAULT_GAS_LIMIT = 1000000;

    /// @notice The address of the gateway contract.
    address public gateway;

    /// @notice Sync function id.
    bytes32 public syncFunctionId;

    /// @notice Verify function id.
    bytes32 public verifyFunctionId;

    /// @notice The latest header that has been committed.
    bytes32 public latestHeader;

    function updateGateway(address _gateway) external onlyOwner {
        gateway = _gateway;
    }

    function updateSyncId(bytes32 _functionId) external onlyOwner {
        syncFunctionId = _functionId;
    }

    function updateVerifyId(bytes32 _functionId) external onlyOwner {
        verifyFunctionId = _functionId;
    }

    /// Note: Only for testnet. The genesis header should be set when initializing the contract.
    function setCheckpointHeader(bytes32 _header) external onlyOwner {
        latestHeader = _header;
    }

    function ensureInitialized() internal view {
        if (gateway == address(0)) {
            revert GatewayNotInitialised();
        }
        if (syncFunctionId == bytes32(0) || verifyFunctionId == bytes32(0)) {
            revert FunctionIdsNotInitialised();
        }
        if (latestHeader == bytes32(0)) {
            revert HeaderNotInitialised();
        }
    }

    /// @notice Inputs of a sync request.
    function requestSync() external payable {
        ensureInitialized();
        bytes memory context;

        ISuccinctGateway(gateway).requestCallback{value: msg.value}(
            syncFunctionId,
            abi.encodePacked(latestHeader),
            context,
            NearX.handleSync.selector,
            DEFAULT_GAS_LIMIT
        );

        emit SyncRequested(latestHeader);
    }

    function handleSync(bytes calldata _output, bytes calldata) external {
        if (msg.sender != gateway || !ISuccinctGateway(gateway).isCallback()) {
            revert NotFromSuccinctGateway(msg.sender);
        }
        // TODO: this does mean we trust the gateway, potentially we add a check here and also store heights

        bytes32 targetHeader = abi.decode(_output, (bytes32));

        // TODO: store block height of last N packed
        latestHeader = targetHeader;

        emit HeadUpdate(targetHeader);
    }

    function requestVerify(TransactionOrReceiptId[] calldata ids)
        external
        payable
    {
        ensureInitialized();
        bytes memory context;
        bytes memory input = abi.encodePacked(
            latestHeader,
            encodePackedIds(ids)
        );

        ISuccinctGateway(gateway).requestCallback{value: msg.value}(
            verifyFunctionId,
            input,
            context,
            NearX.handleVerify.selector,
            DEFAULT_GAS_LIMIT
        );

        emit VerifyRequested(latestHeader, ids);
    }

    function handleVerify(bytes calldata _output, bytes calldata) external {
        if (msg.sender != gateway || !ISuccinctGateway(gateway).isCallback()) {
            revert NotFromSuccinctGateway(msg.sender);
        }
        emit VerifyResult(_output);
    }

    function decodeResults(bytes calldata _output)
        external
        pure
        returns (ProofVerificationResult[] memory)
    {
        return decodePackedResults(_output);
    }
}

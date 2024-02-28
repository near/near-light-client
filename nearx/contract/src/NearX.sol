// SPDX-License-Identifier: MIT
pragma solidity <0.8.20;

import {OwnableUpgradeable} from "@openzeppelin/contracts-upgradeable@4.9.5/access/OwnableUpgradeable.sol";
import {Initializable} from "@openzeppelin/contracts-upgradeable@4.9.5/proxy/utils/Initializable.sol";
import {UUPSUpgradeable} from "@openzeppelin/contracts-upgradeable@4.9.5/proxy/utils/UUPSUpgradeable.sol";
import {ISuccinctGateway} from "./interfaces/ISuccinctGateway.sol";
import {INearX, TransactionOrReceiptId, ProofVerificationResult, encodePackedIds, decodePackedIds, decodePackedResults} from "./interfaces/INearX.sol";
import {DoubleEndedQueue} from "@openzeppelin/contracts@4.9.5/utils/structs/DoubleEndedQueue.sol";

/// @notice The NearX contract is a light client for Near.
contract NearX is INearX, Initializable, OwnableUpgradeable, UUPSUpgradeable {
    using DoubleEndedQueue for DoubleEndedQueue.Bytes32Deque;

    /// @custom:oz-upgrades-unsafe-allow constructor
    constructor() payable {
        _disableInitializers();
    }

    function initialize() public initializer {
        __Ownable_init();
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

    DoubleEndedQueue.Bytes32Deque public lastKnownHeaders;

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

        bytes32 targetHeader = abi.decode(_output, (bytes32));

        latestHeader = targetHeader;

        // TODO: check if we can pop back
        uint256 length = DoubleEndedQueue.length(lastKnownHeaders);
        if (length > 0 && length < 64) {
            DoubleEndedQueue.popBack(lastKnownHeaders);
        }

        DoubleEndedQueue.pushFront(lastKnownHeaders, targetHeader);

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

        bytes32 trustedHeader = abi.decode(_output[:32], (bytes32));
        bytes memory results = _output[32:];

        uint256 length = DoubleEndedQueue.length(lastKnownHeaders);
        require(length < 255);
        bytes32 header;
        uint8 i = 0;
        for (i; i < length; i++) {
            header = DoubleEndedQueue.at(lastKnownHeaders, i);
            if (header == trustedHeader) {
                break;
            }
            if (i == length - 1) {
                revert("Trusted header not found");
            }
        }

        emit VerifyResult(trustedHeader, results);
    }

    function decodeResults(bytes calldata _output)
        external
        pure
        returns (ProofVerificationResult[] memory)
    {
        return decodePackedResults(_output);
    }
}

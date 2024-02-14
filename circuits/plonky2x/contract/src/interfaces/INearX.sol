// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

import "./Bytes.sol";

interface INearX {
    /// @notice Emits event with the new head update.
    event HeadUpdate(bytes32 headerHash);

    /// @notice Inputs of a sync request.
    /// @param trustedHeader The header hash of the trusted block.
    event SyncRequested(bytes32 indexed trustedHeader);

    /// @notice Inputs of a verify request.
    /// @param trustedHeader The header hash of the trusted block.
    /// @param ids The transaction or receipt ids to verify.
    event VerifyRequested(
        bytes32 indexed trustedHeader,
        TransactionOrReceiptId[] indexed ids
    );

    /// @notice Trusted header not found.
    error TrustedHeaderNotFound();

    /// @notice Header not Initialised.
    error HeaderNotInitialised();

    /// @notice Not from Succinct Gateway.
    error NotFromSuccinctGateway(address);

    error GatewayNotInitialised();

    error FunctionIdsNotInitialised();

    /// @notice The result of the verification request
    event VerifyResult(ProofVerificationResult[] results);
}

uint256 constant MAX_LEN = 64;

struct TransactionOrReceiptId {
    bool isTransaction;
    bytes32 id;
    bytes account;
}

function encodePackedIds(TransactionOrReceiptId[] memory ids)
    pure
    returns (bytes memory)
{
    bytes memory output;
    for (uint256 i = 0; i < ids.length; i++) {
        if (i > 0) {
            output = abi.encodePacked(
                output,
                ids[i].isTransaction,
                ids[i].id,
                ids[i].account
            );
        } else {
            output = abi.encodePacked(
                ids[i].isTransaction,
                ids[i].id,
                ids[i].account
            );
        }
    }
    return output;
}

function decodePackedIds(bytes memory _input)
    pure
    returns (TransactionOrReceiptId[] memory)
{
    uint256 iterationLength = 1 + 32 + MAX_LEN;
    uint256 idsLength = _input.length / iterationLength;
    TransactionOrReceiptId[] memory ids = new TransactionOrReceiptId[](
        idsLength
    );

    bytes memory nextBytes;
    uint256 offset = 0;
    for (uint256 i = 0; i < idsLength; i++) {
        (nextBytes, offset) = Bytes.readBytes(_input, offset, iterationLength);
        ids[i] = decodeTransactionOrReceiptId(nextBytes);
    }
    return ids;
}

function decodeTransactionOrReceiptId(bytes memory _input)
    pure
    returns (TransactionOrReceiptId memory id)
{
    bytes memory nextBytes;
    uint256 offset = 0;

    (nextBytes, offset) = Bytes.readBytes(_input, offset, 1);
    id.isTransaction = uint8(bytes1(nextBytes)) != 0;

    (nextBytes, offset) = Bytes.readBytes(_input, offset, 32);
    id.id = abi.decode(nextBytes, (bytes32));

    (nextBytes, offset) = Bytes.readBytes(_input, offset, MAX_LEN);
    id.account = nextBytes;
}

struct ProofVerificationResult {
    bytes32 id;
    bool result;
}

function decodePackedResults(bytes memory _input)
    pure
    returns (ProofVerificationResult[] memory)
{
    uint256 iterationLength = 1 + 32;
    uint256 idsLength = _input.length / iterationLength;
    ProofVerificationResult[] memory results = new ProofVerificationResult[](
        idsLength
    );

    bytes memory nextBytes;
    uint256 offset = 0;
    for (uint256 i = 0; i < idsLength; i++) {
        (nextBytes, offset) = Bytes.readBytes(_input, offset, iterationLength);
        results[i] = decodeProofVerificationResult(nextBytes);
    }
    return results;
}

function decodeProofVerificationResult(bytes memory _input)
    pure
    returns (ProofVerificationResult memory result)
{
    bytes memory nextBytes;
    uint256 offset = 0;
    (nextBytes, offset) = Bytes.readBytes(_input, offset, 32);
    result.id = abi.decode(nextBytes, (bytes32));

    (nextBytes, offset) = Bytes.readBytes(_input, offset, 1);
    result.result = uint8(bytes1(nextBytes)) != 0;
}

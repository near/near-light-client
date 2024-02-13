// SPDX-License-Identifier: MIT
pragma solidity ^0.8.19;

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
    event VerifyResult(TransactionOrReceiptId[] ids);
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
        output = abi.encodePacked(
            output,
            ids[i].isTransaction,
            ids[i].id,
            ids[i].account
        );
    }
    return output;
}

function decodePackedIds(bytes memory _input)
    pure
    returns (TransactionOrReceiptId[] memory)
{
    uint256 idsLength = _input.length / 1 + 32 + MAX_LEN;
    TransactionOrReceiptId[] memory ids = new TransactionOrReceiptId[](
        idsLength
    );

    for (uint256 i = 0; i < idsLength; i++) {
        ids[i] = decodeTransactionOrReceiptId(_input);
    }
    return ids;
}

function decodeTransactionOrReceiptId(bytes memory _input)
    pure
    returns (TransactionOrReceiptId memory id)
{
    id.isTransaction = abi.decode(_input, (bool));
    id.id = abi.decode(_input, (bytes32));
    bytes32 accountX = abi.decode(_input, (bytes32));
    bytes32 accountY = abi.decode(_input, (bytes32));
    id.account = abi.encodePacked(accountX, accountY);
}

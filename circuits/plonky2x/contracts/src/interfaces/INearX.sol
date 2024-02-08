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
}

struct TransactionOrReceiptId {
    bool isTransaction;
    bytes32 id;
    string account;
}

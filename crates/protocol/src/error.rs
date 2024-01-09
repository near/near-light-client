use thiserror::Error;

#[derive(Error, Debug, PartialEq, Eq)]
pub enum Error {
    #[error("Block already verified")]
    BlockAlreadyVerified,
    #[error("Block not in current or next epoch")]
    BlockNotCurrentOrNextEpoch,
    #[error("Signature invalid")]
    SignatureInvalid,
    #[error("Not enough approved stake")]
    NotEnoughApprovedStake,
    #[error("Block is in the next epoch but no new set")]
    NextBpsInvalid,
    #[error("Validator not signed")]
    ValidatorNotSigned,
}

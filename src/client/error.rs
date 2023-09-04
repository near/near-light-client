#[derive(Debug, Eq, PartialEq)]
pub enum Error {
    BlockAlreadyVerified,
    BlockNotCurrentOrNextEpoch,
    BlockMissingNextBps,
    SignatureInvalid,
    NotEnoughApprovedStake,
    NextBpsInvalid,
}

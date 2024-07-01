use near_light_client_rpc::{prelude::GetProof, TransactionOrReceiptId};
use serde::{Deserialize, Serialize};

pub(crate) type PriorityWeight = u32;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionOrReceiptIdNewtype(pub TransactionOrReceiptId);

impl From<TransactionOrReceiptId> for TransactionOrReceiptIdNewtype {
    fn from(id: TransactionOrReceiptId) -> Self {
        Self(id)
    }
}
impl std::hash::Hash for TransactionOrReceiptIdNewtype {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        let (is_transaction, id, account) = match &self.0 {
            GetProof::Transaction {
                transaction_hash,
                sender_id,
            } => (true, transaction_hash, sender_id),
            GetProof::Receipt {
                receipt_id,
                receiver_id,
            } => (false, receipt_id, receiver_id),
        };
        is_transaction.hash(state);
        id.hash(state);
        account.hash(state);
    }
}

impl PartialEq for TransactionOrReceiptIdNewtype {
    fn eq(&self, other: &Self) -> bool {
        match (&self.0, &other.0) {
            (
                TransactionOrReceiptId::Transaction {
                    transaction_hash: l1,
                    sender_id: l2,
                },
                TransactionOrReceiptId::Transaction {
                    transaction_hash: r1,
                    sender_id: r2,
                },
            ) => l1 == r1 && l2 == r2,
            (
                TransactionOrReceiptId::Receipt {
                    receipt_id: l1,
                    receiver_id: l2,
                },
                TransactionOrReceiptId::Receipt {
                    receipt_id: r1,
                    receiver_id: r2,
                },
            ) => l1 == r1 && l2 == r2,
            _ => false,
        }
    }
}

impl Eq for TransactionOrReceiptIdNewtype {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegistryInfo {
    pub id: usize,
    // Their weight in the shared queue
    pub weight: PriorityWeight,
}

#[cfg(test)]
mod tests {

    use std::str::FromStr;

    use near_light_client_protocol::near_account_id::AccountId;
    use test_utils::CryptoHash;

    use super::*;

    #[test]
    fn test_transaction_or_receipt_id_eq() {
        let transaction1 = TransactionOrReceiptIdNewtype(TransactionOrReceiptId::Transaction {
            transaction_hash: CryptoHash::default(),
            sender_id: AccountId::from_str("sender1").unwrap(),
        });
        let transaction2 = TransactionOrReceiptIdNewtype(TransactionOrReceiptId::Transaction {
            transaction_hash: CryptoHash::default(),
            sender_id: AccountId::from_str("sender1").unwrap(),
        });
        assert!(transaction1 == transaction2);

        let receipt1 = TransactionOrReceiptIdNewtype(TransactionOrReceiptId::Receipt {
            receipt_id: CryptoHash::default(),
            receiver_id: AccountId::from_str("receiver1").unwrap(),
        });
        let receipt2 = TransactionOrReceiptIdNewtype(TransactionOrReceiptId::Receipt {
            receipt_id: CryptoHash::default(),
            receiver_id: AccountId::from_str("receiver1").unwrap(),
        });
        assert!(receipt1 == receipt2);

        let transaction3 = TransactionOrReceiptIdNewtype(TransactionOrReceiptId::Transaction {
            transaction_hash: CryptoHash::default(),
            sender_id: AccountId::from_str("sender2").unwrap(),
        });
        assert!(transaction1 != transaction3);

        let receipt3 = TransactionOrReceiptIdNewtype(TransactionOrReceiptId::Receipt {
            receipt_id: CryptoHash::default(),
            receiver_id: AccountId::from_str("receiver2").unwrap(),
        });
        assert!(receipt1 != receipt3);

        assert!(transaction1 != receipt1);
    }
}

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

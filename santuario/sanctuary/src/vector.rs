use serde::{Deserialize, Serialize};
use crate::{RecordSigner, SanctuaryError, SanctuaryRecord};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ContextVectorRecord {
    pub vector_id: String,
    pub dimensions: usize,
    pub values: Vec<f32>,
    pub metadata: serde_json::Value,
}

impl ContextVectorRecord {
    /// Serializes the context vector and signs it with the provided signer.
    pub fn serialize_and_sign<S: RecordSigner>(
        &self,
        signer: &S,
        seq: u64,
        sender: String,
    ) -> Result<SanctuaryRecord, SanctuaryError> {
        let payload = serde_json::to_vec(self)?;
        let signature = signer.sign(&payload)?;
        
        Ok(SanctuaryRecord {
            seq,
            ts_utc: crate::now_utc(),
            sender,
            payload,
            signature,
        })
    }

    /// Verifies the signature of the record and deserializes the inner context vector.
    pub fn verify_and_deserialize<S: RecordSigner>(
        record: &SanctuaryRecord,
        verifier: &S,
    ) -> Result<Self, SanctuaryError> {
        verifier.verify(&record.payload, &record.signature)?;
        let context_vector: Self = serde_json::from_slice(&record.payload)?;
        Ok(context_vector)
    }

    /// Fast neural search simulation mapping over unencrypted memory buffer.
    /// In production, once signatures are verified on load, similarity calculations
    /// run directly on the floats without any cryptographic overhead.
    pub fn cosine_similarity(&self, other: &Self) -> Result<f32, SanctuaryError> {
        if self.dimensions != other.dimensions || self.values.len() != other.values.len() {
            return Err(SanctuaryError::Corrupt("Dimensions mismatch for neural search comparison".to_string()));
        }

        let mut dot_product = 0.0;
        let mut norm_a = 0.0;
        let mut norm_b = 0.0;

        for (a, b) in self.values.iter().zip(other.values.iter()) {
            dot_product += a * b;
            norm_a += a * a;
            norm_b += b * b;
        }

        if norm_a == 0.0 || norm_b == 0.0 {
            return Ok(0.0);
        }

        Ok(dot_product / (norm_a.sqrt() * norm_b.sqrt()))
    }
}

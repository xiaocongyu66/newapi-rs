use sha2::{Digest, Sha256};

/// Build the normalized cache key from the canonical request body and the
/// resolved upstream model. The caller must strip volatile fields first.
pub fn key(canonical_json: &[u8], model: &str) -> String {
    let mut digest = Sha256::new();
    digest.update(model.as_bytes());
    digest.update([0u8]);
    digest.update(canonical_json);
    hex::encode(digest.finalize())
}

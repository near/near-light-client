use crate::config::Config;
use anyhow::anyhow;
use kzg::{
    eip_4844::{BYTES_PER_BLOB, TRUSTED_SETUP_PATH},
    Fr, KZGSettings, G1,
};
use rand::{Rng, SeedableRng};
use rust_kzg_blst::{
    eip_4844::{
        blob_to_kzg_commitment_rust, blob_to_polynomial_rust, bytes_to_blob,
        compute_kzg_proof_rust, evaluate_polynomial_in_evaluation_form_rust,
        load_trusted_setup_filename_rust, verify_kzg_proof_batch, verify_kzg_proof_rust,
    },
    types::{fr::FsFr, g1::FsG1, kzg_settings::FsKZGSettings},
};
use serde::{Deserialize, Serialize};
use serde_with::serde_as;

#[derive(Debug)]
pub struct Commitment {
    pub commitment: FsG1,
    pub blob: Vec<FsFr>,
}

impl Commitment {
    pub fn new(trusted_setup: &FsKZGSettings, mut bytes: Vec<u8>) -> anyhow::Result<Self> {
        if bytes.len() < BYTES_PER_BLOB {
            bytes.resize(BYTES_PER_BLOB, 0);
        }

        // TODO: here we don't need to build blobs, just commitments over fields and emit those
        let blob = bytes_to_blob(&bytes).map_err(|e| anyhow!(format!("Bytes to blob {}", e)))?;

        let commitment = blob_to_kzg_commitment_rust(&blob, trusted_setup);
        Ok(Self { blob, commitment })
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct CommitmentExternal {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub commitment: [u8; 48],
    #[serde_as(as = "Vec<serde_with::hex::Hex>")]
    pub blob: Vec<[u8; 32]>,
}

impl From<Commitment> for CommitmentExternal {
    fn from(c: Commitment) -> Self {
        Self {
            commitment: c.commitment.to_bytes(),
            blob: c
                .blob
                .iter()
                .map(|x| x.to_bytes())
                .collect::<Vec<[u8; 32]>>(),
        }
    }
}

#[derive(Debug)]
pub struct Proof {
    pub proof: FsG1,
    pub z_fr: FsFr,
    pub y_fr: FsFr,
    pub commitment: FsG1,
}

impl Proof {
    // Dead, replaced with multiproofs TODO: remove
    pub fn from(trusted_setup: &FsKZGSettings, commitment: Commitment) -> Self {
        // Generate 8 random numbers between 0..25
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();

        let z_fr = trusted_setup.get_roots_of_unity_at(rng.gen_range(0..25));
        let poly = blob_to_polynomial_rust(&commitment.blob);
        let (proof, computed_y) = compute_kzg_proof_rust(&commitment.blob, &z_fr, trusted_setup);
        let y_fr = evaluate_polynomial_in_evaluation_form_rust(&poly, &z_fr, trusted_setup);

        // Compare the recently evaluated y to the computed y
        assert!(y_fr.equals(&computed_y));
        Self {
            proof,
            z_fr,
            y_fr,
            commitment: commitment.commitment,
        }
    }
    pub fn prove(trusted_setup: &FsKZGSettings, commitment: Commitment) -> Vec<Self> {
        let mut rng = rand_chacha::ChaCha20Rng::from_entropy();

        let mut proofs = Vec::new();

        for _ in 0..8 {
            let z_fr = trusted_setup.get_roots_of_unity_at(rng.gen_range(0..25));
            let poly = blob_to_polynomial_rust(&commitment.blob);
            let (proof, computed_y) =
                compute_kzg_proof_rust(&commitment.blob, &z_fr, trusted_setup);
            let y_fr = evaluate_polynomial_in_evaluation_form_rust(&poly, &z_fr, trusted_setup);

            // Compare the recently evaluated y to the computed y
            if y_fr.equals(&computed_y) {
                proofs.push(Self {
                    proof,
                    z_fr,
                    y_fr,
                    commitment: commitment.commitment,
                })
            }
        }
        proofs
    }
    pub fn verify_batch(proofs: &[Self], trusted_setup: &FsKZGSettings) -> bool {
        let commitments = proofs.iter().map(|p| p.commitment).collect::<Vec<FsG1>>();
        let zs = proofs.iter().map(|p| p.z_fr).collect::<Vec<FsFr>>();
        let ys = proofs.iter().map(|p| p.y_fr).collect::<Vec<FsFr>>();
        let proofs = proofs.iter().map(|p| p.proof).collect::<Vec<FsG1>>();

        verify_kzg_proof_batch(&commitments, &zs, &ys, &proofs, trusted_setup)
    }
}

#[serde_as]
#[derive(Debug, Serialize, Deserialize)]
pub struct ProofExternal {
    #[serde_as(as = "serde_with::hex::Hex")]
    pub proof: [u8; 48],
    #[serde_as(as = "serde_with::hex::Hex")]
    pub z_fr: [u8; 32],
    #[serde_as(as = "serde_with::hex::Hex")]
    pub y_fr: [u8; 32],
    #[serde_as(as = "serde_with::hex::Hex")]
    pub commitment: [u8; 48],
}

impl From<Proof> for ProofExternal {
    fn from(p: Proof) -> Self {
        Self {
            proof: p.proof.to_bytes(),
            z_fr: p.z_fr.to_bytes(),
            y_fr: p.y_fr.to_bytes(),
            commitment: p.commitment.to_bytes(),
        }
    }
}

pub fn setup(config: &Config) -> FsKZGSettings {
    load_trusted_setup_filename_rust(
        &config
            .trusted_setup_path
            .as_ref()
            .map(|x| format!("{}", x.display()))
            .unwrap_or(TRUSTED_SETUP_PATH.to_string()),
    )
}

pub fn init_trusted_setup(file: &str) -> FsKZGSettings {
    load_trusted_setup_filename_rust(file)
}

#[cfg(test)]

mod tests {
    use super::*;

    const TRUSTED_SETUP: &str = "trusted-setup";

    fn init_trusted_setup() -> FsKZGSettings {
        super::init_trusted_setup(TRUSTED_SETUP)
    }

    #[test]
    fn test_create_commitment_from_bytes() {
        let setup = init_trusted_setup();
        let bytes = [48_u8; 131072]; // Fixme: blob must be this size
        let commitment = Commitment::new(&setup, bytes.to_vec()).unwrap();
        println!("Commitment: {:?}", commitment.commitment);
    }

    #[test]
    fn blackbox_compute_verify_proof() {
        let setup = init_trusted_setup();
        let bytes = [48_u8; 131072]; // Fixme: blob must be this size
        let commitment = Commitment::new(&setup, bytes.to_vec()).unwrap();

        let proof = Proof::from(&setup, commitment);

        assert!(Proof::verify_batch(&[proof], &setup));
    }
}

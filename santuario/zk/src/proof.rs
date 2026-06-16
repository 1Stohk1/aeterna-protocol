use crate::circuits::DnaMutationCircuit;
use ark_bn254::{Bn254, Fr};
use ark_groth16::{Groth16, Proof, ProvingKey, PreparedVerifyingKey, VerifyingKey};
use ark_snark::{SNARK, CircuitSpecificSetupSNARK};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use ark_relations::r1cs::SynthesisError;
use ark_std::rand::rngs::StdRng;
use ark_std::rand::SeedableRng;
use anyhow::Result;

/// Esegue il setup dei parametri (Proving Key e Verifying Key) per un circuito di lunghezza data.
pub fn setup_keys(
    sequence_len: usize,
) -> Result<(ProvingKey<Bn254>, VerifyingKey<Bn254>), SynthesisError> {
    // Creiamo un circuito "vuoto" con Option impostati a None per definire la topologia R1CS
    let circuit = DnaMutationCircuit::<Fr> {
        manifest_hash: None,
        task_id: None,
        gc_content_count: None,
        hamming_distance: None,
        ref_hash: None,
        obs_hash: None,
        ref_seq: None,
        obs_seq: None,
        sequence_len,
    };

    let mut rng = StdRng::seed_from_u64(42); // Setup trusted deterministico ad uso test/simulazione
    let (pk, vk) = Groth16::<Bn254>::setup(circuit, &mut rng)?;

    Ok((pk, vk))
}

/// Genera la proof zk-SNARK
pub fn generate_poc_proof(
    pk: &ProvingKey<Bn254>,
    manifest_hash: Fr,
    task_id: Fr,
    gc_content_count: u32,
    hamming_distance: u32,
    ref_hash: Fr,
    obs_hash: Fr,
    ref_seq: Vec<Fr>,
    obs_seq: Vec<Fr>,
    sequence_len: usize,
) -> Result<Proof<Bn254>, SynthesisError> {
    let circuit = DnaMutationCircuit::<Fr> {
        manifest_hash: Some(manifest_hash),
        task_id: Some(task_id),
        gc_content_count: Some(gc_content_count),
        hamming_distance: Some(hamming_distance),
        ref_hash: Some(ref_hash),
        obs_hash: Some(obs_hash),
        ref_seq: Some(ref_seq),
        obs_seq: Some(obs_seq),
        sequence_len,
    };

    let mut rng = StdRng::seed_from_u64(42);
    Groth16::<Bn254>::prove(pk, circuit, &mut rng)
}

/// Verifica la proof zk-SNARK utilizzando la PreparedVerifyingKey
pub fn verify_poc_proof(
    pvk: &PreparedVerifyingKey<Bn254>,
    proof: &Proof<Bn254>,
    manifest_hash: Fr,
    task_id: Fr,
    gc_content_count: u32,
    hamming_distance: u32,
    ref_hash: Fr,
    obs_hash: Fr,
) -> Result<bool, SynthesisError> {
    let public_inputs = vec![
        manifest_hash,
        task_id,
        Fr::from(gc_content_count),
        Fr::from(hamming_distance),
        ref_hash,
        obs_hash,
    ];

    Groth16::<Bn254>::verify_proof(pvk, proof, &public_inputs)
}

// ============================================================================
//  Serializzazione e Deserializzazione Canoniche
// ============================================================================

pub fn serialize_proof(proof: &Proof<Bn254>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    proof.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

pub fn deserialize_proof(bytes: &[u8]) -> Result<Proof<Bn254>> {
    let proof = Proof::<Bn254>::deserialize_compressed(bytes)?;
    Ok(proof)
}

pub fn serialize_proving_key(pk: &ProvingKey<Bn254>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    pk.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

pub fn deserialize_proving_key(bytes: &[u8]) -> Result<ProvingKey<Bn254>> {
    let pk = ProvingKey::<Bn254>::deserialize_compressed(bytes)?;
    Ok(pk)
}

pub fn serialize_verifying_key(vk: &VerifyingKey<Bn254>) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    vk.serialize_compressed(&mut bytes)?;
    Ok(bytes)
}

pub fn deserialize_verifying_key(bytes: &[u8]) -> Result<VerifyingKey<Bn254>> {
    let vk = VerifyingKey::<Bn254>::deserialize_compressed(bytes)?;
    Ok(vk)
}

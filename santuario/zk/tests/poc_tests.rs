use santuario_zk::circuits::{
    dna_to_field_elements, calculate_rolling_hash, calculate_gc_count,
    calculate_hamming_distance, DnaMutationCircuit,
};
use santuario_zk::proof::{
    setup_keys, generate_poc_proof, verify_poc_proof,
    serialize_proof, deserialize_proof,
};
use ark_bn254::Fr;
use ark_relations::r1cs::{ConstraintSystem, ConstraintSynthesizer};
use ark_groth16::prepare_verifying_key;

#[test]
fn test_circuit_satisfaction_valid() {
    let ref_str = "ACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGT"; // 64 bases
    let obs_str = "ACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGC"; // 1 mutation (T->C)

    let ref_seq = dna_to_field_elements::<Fr>(ref_str);
    let obs_seq = dna_to_field_elements::<Fr>(obs_str);

    let manifest_hash = Fr::from(11111u32);
    let task_id = Fr::from(22222u32);
    let gc_content_count = calculate_gc_count(&obs_seq);
    let hamming_distance = calculate_hamming_distance(&ref_seq, &obs_seq);
    let ref_hash = calculate_rolling_hash(&ref_seq);
    let obs_hash = calculate_rolling_hash(&obs_seq);

    let circuit = DnaMutationCircuit::<Fr> {
        manifest_hash: Some(manifest_hash),
        task_id: Some(task_id),
        gc_content_count: Some(gc_content_count),
        hamming_distance: Some(hamming_distance),
        ref_hash: Some(ref_hash),
        obs_hash: Some(obs_hash),
        ref_seq: Some(ref_seq),
        obs_seq: Some(obs_seq),
        sequence_len: 64,
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(cs.is_satisfied().unwrap(), "Constraint system should be satisfied for valid inputs");
}

#[test]
fn test_circuit_satisfaction_invalid_gc() {
    let ref_str = "ACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGT";
    let obs_str = "ACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGC";

    let ref_seq = dna_to_field_elements::<Fr>(ref_str);
    let obs_seq = dna_to_field_elements::<Fr>(obs_str);

    let manifest_hash = Fr::from(11111u32);
    let task_id = Fr::from(22222u32);
    // Claiming an incorrect GC content count
    let gc_content_count = calculate_gc_count(&obs_seq) + 1;
    let hamming_distance = calculate_hamming_distance(&ref_seq, &obs_seq);
    let ref_hash = calculate_rolling_hash(&ref_seq);
    let obs_hash = calculate_rolling_hash(&obs_seq);

    let circuit = DnaMutationCircuit::<Fr> {
        manifest_hash: Some(manifest_hash),
        task_id: Some(task_id),
        gc_content_count: Some(gc_content_count),
        hamming_distance: Some(hamming_distance),
        ref_hash: Some(ref_hash),
        obs_hash: Some(obs_hash),
        ref_seq: Some(ref_seq),
        obs_seq: Some(obs_seq),
        sequence_len: 64,
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(!cs.is_satisfied().unwrap(), "Should fail for incorrect GC content count claim");
}

#[test]
fn test_circuit_satisfaction_invalid_hamming() {
    let ref_str = "ACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGT";
    let obs_str = "ACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGC";

    let ref_seq = dna_to_field_elements::<Fr>(ref_str);
    let obs_seq = dna_to_field_elements::<Fr>(obs_str);

    let manifest_hash = Fr::from(11111u32);
    let task_id = Fr::from(22222u32);
    let gc_content_count = calculate_gc_count(&obs_seq);
    // Claiming a different Hamming distance
    let hamming_distance = calculate_hamming_distance(&ref_seq, &obs_seq) + 1;
    let ref_hash = calculate_rolling_hash(&ref_seq);
    let obs_hash = calculate_rolling_hash(&obs_seq);

    let circuit = DnaMutationCircuit::<Fr> {
        manifest_hash: Some(manifest_hash),
        task_id: Some(task_id),
        gc_content_count: Some(gc_content_count),
        hamming_distance: Some(hamming_distance),
        ref_hash: Some(ref_hash),
        obs_hash: Some(obs_hash),
        ref_seq: Some(ref_seq),
        obs_seq: Some(obs_seq),
        sequence_len: 64,
    };

    let cs = ConstraintSystem::<Fr>::new_ref();
    circuit.generate_constraints(cs.clone()).unwrap();

    assert!(!cs.is_satisfied().unwrap(), "Should fail for incorrect Hamming distance claim");
}

#[test]
fn test_groth16_proving_and_verification() {
    let sequence_len = 64;

    // 1. Setup keys
    let (pk, vk) = setup_keys(sequence_len).expect("Keys setup failed");
    let pvk = prepare_verifying_key(&vk);

    // 2. Prover inputs and witnesses
    let ref_str = "ACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGT";
    let obs_str = "ACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGTACGC";

    let ref_seq = dna_to_field_elements::<Fr>(ref_str);
    let obs_seq = dna_to_field_elements::<Fr>(obs_str);

    let manifest_hash = Fr::from(123456789u32);
    let task_id = Fr::from(987654321u32);
    let gc_content_count = calculate_gc_count(&obs_seq);
    let hamming_distance = calculate_hamming_distance(&ref_seq, &obs_seq);
    let ref_hash = calculate_rolling_hash(&ref_seq);
    let obs_hash = calculate_rolling_hash(&obs_seq);

    // 3. Generate proof
    let proof = generate_poc_proof(
        &pk,
        manifest_hash,
        task_id,
        gc_content_count,
        hamming_distance,
        ref_hash,
        obs_hash,
        ref_seq,
        obs_seq,
        sequence_len,
    ).expect("Proof generation failed");

    // Test serialization/deserialization of proof
    let serialized = serialize_proof(&proof).expect("Serialization failed");
    let deserialized_proof = deserialize_proof(&serialized).expect("Deserialization failed");

    // 4. Verify proof with correct parameters
    let is_valid = verify_poc_proof(
        &pvk,
        &deserialized_proof,
        manifest_hash,
        task_id,
        gc_content_count,
        hamming_distance,
        ref_hash,
        obs_hash,
    ).expect("Proof verification failed");

    assert!(is_valid, "Valid proof should be successfully verified");

    // 5. Verify proof fails with tampered public parameters
    // Tamper manifest_hash
    let bad_manifest_hash = Fr::from(999999999u32);
    let is_valid_bad_manifest = verify_poc_proof(
        &pvk,
        &deserialized_proof,
        bad_manifest_hash,
        task_id,
        gc_content_count,
        hamming_distance,
        ref_hash,
        obs_hash,
    ).expect("Proof verification failed");
    assert!(!is_valid_bad_manifest, "Verification should fail with tampered manifest hash");

    // Tamper task_id
    let bad_task_id = Fr::from(888888888u32);
    let is_valid_bad_task = verify_poc_proof(
        &pvk,
        &deserialized_proof,
        manifest_hash,
        bad_task_id,
        gc_content_count,
        hamming_distance,
        ref_hash,
        obs_hash,
    ).expect("Proof verification failed");
    assert!(!is_valid_bad_task, "Verification should fail with tampered task ID");

    // Tamper GC count
    let is_valid_bad_gc = verify_poc_proof(
        &pvk,
        &deserialized_proof,
        manifest_hash,
        task_id,
        gc_content_count + 1,
        hamming_distance,
        ref_hash,
        obs_hash,
    ).expect("Proof verification failed");
    assert!(!is_valid_bad_gc, "Verification should fail with tampered GC count");
}

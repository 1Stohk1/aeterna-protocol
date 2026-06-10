use ark_ff::PrimeField;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_r1cs_std::prelude::*;
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::alloc::AllocVar;
use ark_r1cs_std::eq::EqGadget;
use ark_std::vec::Vec;

/// A circuit for proving correctness of a DNA mutation scan.
/// Codificazione dei nucleotidi:
/// - A -> 0
/// - C -> 1
/// - G -> 2
/// - T -> 3
pub struct DnaMutationCircuit<F: PrimeField> {
    // --- Public Inputs ---
    pub manifest_hash: Option<F>,
    pub task_id: Option<F>,
    pub gc_content_count: Option<u32>,
    pub hamming_distance: Option<u32>,
    pub ref_hash: Option<F>,
    pub obs_hash: Option<F>,

    // --- Private Witnesses ---
    pub ref_seq: Option<Vec<F>>,
    pub obs_seq: Option<Vec<F>>,

    // --- Configuration ---
    pub sequence_len: usize,
}

impl<F: PrimeField> ConstraintSynthesizer<F> for DnaMutationCircuit<F> {
    fn generate_constraints(self, cs: ConstraintSystemRef<F>) -> Result<(), SynthesisError> {
        // 1. Allocate Public Inputs
        let manifest_hash_var = FpVar::new_input(ark_relations::ns!(cs, "manifest_hash"), || {
            self.manifest_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let task_id_var = FpVar::new_input(ark_relations::ns!(cs, "task_id"), || {
            self.task_id.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let gc_content_count_var = FpVar::new_input(ark_relations::ns!(cs, "gc_content_count"), || {
            self.gc_content_count
                .map(|c| F::from(c))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let hamming_distance_var = FpVar::new_input(ark_relations::ns!(cs, "hamming_distance"), || {
            self.hamming_distance
                .map(|d| F::from(d))
                .ok_or(SynthesisError::AssignmentMissing)
        })?;

        let ref_hash_var = FpVar::new_input(ark_relations::ns!(cs, "ref_hash"), || {
            self.ref_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let obs_hash_var = FpVar::new_input(ark_relations::ns!(cs, "obs_hash"), || {
            self.obs_hash.ok_or(SynthesisError::AssignmentMissing)
        })?;

        // Trivial dummy constraints to bind manifest_hash and task_id variables
        // if they are not explicitly involved in arithmetic.
        let manifest_plus_task = &manifest_hash_var + &task_id_var;
        let manifest_plus_task_squared = &manifest_plus_task * &manifest_plus_task;
        manifest_plus_task_squared.enforce_equal(&manifest_plus_task_squared)?;

        // 2. Allocate Private Witnesses (direct cs.clone() namespace to avoid static macro tracing restrictions)
        let ref_seq_vars: Vec<FpVar<F>> = self.ref_seq.as_ref()
            .map(|seq| {
                seq.iter()
                    .map(|&val| {
                        FpVar::new_witness(cs.clone(), || Ok(val))
                    })
                    .collect::<Result<Vec<FpVar<F>>, SynthesisError>>()
            })
            .unwrap_or_else(|| {
                (0..self.sequence_len)
                    .map(|_| {
                        FpVar::new_witness(cs.clone(), || {
                            Result::<F, SynthesisError>::Err(SynthesisError::AssignmentMissing)
                        })
                    })
                    .collect::<Result<Vec<FpVar<F>>, SynthesisError>>()
            })?;

        let obs_seq_vars: Vec<FpVar<F>> = self.obs_seq.as_ref()
            .map(|seq| {
                seq.iter()
                    .map(|&val| {
                        FpVar::new_witness(cs.clone(), || Ok(val))
                    })
                    .collect::<Result<Vec<FpVar<F>>, SynthesisError>>()
            })
            .unwrap_or_else(|| {
                (0..self.sequence_len)
                    .map(|_| {
                        FpVar::new_witness(cs.clone(), || {
                            Result::<F, SynthesisError>::Err(SynthesisError::AssignmentMissing)
                        })
                    })
                    .collect::<Result<Vec<FpVar<F>>, SynthesisError>>()
            })?;

        // Ensure both sequences have the expected length
        if ref_seq_vars.len() != self.sequence_len || obs_seq_vars.len() != self.sequence_len {
            return Err(SynthesisError::Unsatisfiable);
        }

        // 3. Domain Constraints (x in {0, 1, 2, 3})
        for x in ref_seq_vars.iter().chain(obs_seq_vars.iter()) {
            let x_minus_1 = x - &FpVar::Constant(F::one());
            let x_minus_2 = x - &FpVar::Constant(F::from(2u32));
            let x_minus_3 = x - &FpVar::Constant(F::from(3u32));

            let y = x * &x_minus_1;
            let z = &y * &x_minus_2;
            let prod = &z * &x_minus_3;
            prod.enforce_equal(&FpVar::zero())?;
        }

        // 4. GC Content Count Constraint
        // formula: 2 * is_gc_i = obs_seq[i] * (3 - obs_seq[i])
        // is_gc_i = obs_seq[i] * (3 - obs_seq[i]) * 2^-1
        let two_inv = F::from(2u32)
            .inverse()
            .ok_or(SynthesisError::Unsatisfiable)?;

        let mut gc_sum = FpVar::zero();
        for x in &obs_seq_vars {
            let three_minus_x = &FpVar::Constant(F::from(3u32)) - x;
            let prod = x * &three_minus_x;
            let is_gc_i = &prod * &FpVar::Constant(two_inv);
            gc_sum += &is_gc_i;
        }
        gc_sum.enforce_equal(&gc_content_count_var)?;

        // 5. Hamming Distance Constraint
        let mut hamming_sum = FpVar::zero();
        for i in 0..self.sequence_len {
            let is_eq = ref_seq_vars[i].is_eq(&obs_seq_vars[i])?;
            let is_diff = is_eq.not();
            hamming_sum += FpVar::from(is_diff);
        }
        hamming_sum.enforce_equal(&hamming_distance_var)?;

        // 6. Sequence Commitment (Rabin Rolling Fingerprint Hash)
        // H_0 = seq[0]
        // H_i = H_{i-1} * 31 + seq[i]
        let beta = F::from(31u32);

        // Reference sequence hash
        let mut ref_h = ref_seq_vars[0].clone();
        for i in 1..self.sequence_len {
            ref_h = &ref_h * &FpVar::Constant(beta) + &ref_seq_vars[i];
        }
        ref_h.enforce_equal(&ref_hash_var)?;

        // Observed sequence hash
        let mut obs_h = obs_seq_vars[0].clone();
        for i in 1..self.sequence_len {
            obs_h = &obs_h * &FpVar::Constant(beta) + &obs_seq_vars[i];
        }
        obs_h.enforce_equal(&obs_hash_var)?;

        Ok(())
    }
}

// ============================================================================
//  Helper Functions
// ============================================================================

/// Mappa una stringa DNA ("ACGT") in elementi del campo finito
pub fn dna_to_field_elements<F: PrimeField>(seq: &str) -> Vec<F> {
    seq.chars()
        .map(|c| {
            let val = match c {
                'A' | 'a' => 0u32,
                'C' | 'c' => 1u32,
                'G' | 'g' => 2u32,
                'T' | 't' => 3u32,
                _ => 0u32,
            };
            F::from(val)
        })
        .collect()
}

/// Calcola il rolling hash polinomiale di una sequenza
pub fn calculate_rolling_hash<F: PrimeField>(seq: &[F]) -> F {
    if seq.is_empty() {
        return F::zero();
    }
    let mut h = seq[0];
    for &val in seq.iter().skip(1) {
        h = h * F::from(31u32) + val;
    }
    h
}

/// Calcola il numero di basi C o G
pub fn calculate_gc_count<F: PrimeField>(seq: &[F]) -> u32 {
    let mut count = 0;
    for &val in seq {
        if val == F::from(1u32) || val == F::from(2u32) {
            count += 1;
        }
    }
    count
}

/// Calcola la distanza di Hamming tra due sequenze
pub fn calculate_hamming_distance<F: PrimeField>(ref_seq: &[F], obs_seq: &[F]) -> u32 {
    ref_seq.iter().zip(obs_seq.iter()).filter(|(&r, &o)| r != o).count() as u32
}

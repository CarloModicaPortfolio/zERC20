use anyhow::{Context as _, anyhow};
use ark_bn254::Fr;
use ark_ff::Zero;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use folding_schemes::FoldingScheme;
use rand::Rng;
use std::{fs, io::Cursor, path::Path};
use zkp::{
    nova::{
        innocence_nova::{InnocenceCircuit, InnocenceExternalInputs, dummy_innocence_ext_input},
        params::NovaParams,
    },
    utils::poseidon::utils::{circom_poseidon2_config, circom_poseidon3_config},
};

use ark_bn254::G1Projective as G1;
use ark_grumpkin::Projective as G2;
use folding_schemes::folding::nova::IVCProof;

pub fn load_innocence_params<const DEPTH: usize>(
    artifacts_dir: &Path,
) -> anyhow::Result<NovaParams<InnocenceCircuit<Fr, DEPTH>>> {
    let poseidon2_params = circom_poseidon2_config::<Fr>();
    let poseidon3_params = circom_poseidon3_config();
    let pp = fs::read(artifacts_dir.join("innocence_nova_pp.bin"))
        .context("failed to read innocence_nova_pp.bin")?;
    let vp = fs::read(artifacts_dir.join("innocence_nova_vp.bin"))
        .context("failed to read innocence_nova_vp.bin")?;
    NovaParams::from_bytes((poseidon2_params, poseidon3_params), pp, vp)
        .map_err(|err| anyhow!("failed to deserialize innocence nova params: {}", err))
}

pub fn generate_innocence_proof<const DEPTH: usize>(
    artifacts_dir: &Path,
    recipient: Fr,
    ofac_root: Fr,
    external_inputs: Vec<InnocenceExternalInputs<Fr, DEPTH>>,
) -> anyhow::Result<Vec<u8>> {
    let nova_params = load_innocence_params::<DEPTH>(artifacts_dir)
        .context("failed to load innocence Nova params")?;

    let z_0 = vec![ofac_root, recipient, Fr::zero()];

    let mut rng = rand::thread_rng();

    let num_dummy_steps = rng.gen_range(1..10);

    log::info!(
        "Start IVC proof generation for proof of innocence with {} transfers and {} dummy steps (total {})",
        external_inputs.len(),
        num_dummy_steps,
        external_inputs.len() + num_dummy_steps
    );

    let mut nova = nova_params
        .initial_nova(z_0)
        .context("failed to initialize innocence Nova")?;

    for ext_input in external_inputs {
        nova.prove_step(&mut rng, ext_input, None)
            .context("failed to prove step in innocence Nova")?;
    }

    for _ in 0..num_dummy_steps {
        let dummy = dummy_innocence_ext_input::<Fr, DEPTH>(Fr::zero());
        nova.prove_step(&mut rng, dummy, None)
            .context("failed to prove dummy step in innocence Nova")?;
    }

    let ivc_proof = nova.ivc_proof();
    nova_params
        .verify(ivc_proof.clone())
        .context("failed to verify innocence Nova proof")?;
    log::info!("Innocence Nova proof generated and verified");

    let mut proof_bytes = Vec::new();
    ivc_proof
        .serialize_uncompressed(&mut proof_bytes)
        .context("failed to serialize innocence Nova proof")?;

    Ok(proof_bytes)
}

pub fn verify_innocence_proof<const DEPTH: usize>(
    artifacts_dir: &Path,
    proof_bytes: &[u8],
    recipient: Fr,
    total_teleported: Fr,
    ofac_root: Fr,
) -> anyhow::Result<()> {
    let nova_params = load_innocence_params::<DEPTH>(artifacts_dir)
        .context("failed to load innocence Nova params")?;

    let mut cursor = Cursor::new(proof_bytes);
    let ivc_proof: IVCProof<G1, G2> =
        CanonicalDeserialize::deserialize_uncompressed(&mut cursor)
            .context("failed to deserialize innocence IVC proof")?;

    nova_params
        .verify(ivc_proof.clone())
        .context("IVC proof verification failed")?;

    let nova = nova_params
        .nova_from_ivc_proof(ivc_proof)
        .map_err(|e| anyhow!("failed to reconstruct Nova from IVC proof: {}", e))?;

    let z_i = &nova.z_i;
    if z_i.len() != 3 {
        anyhow::bail!("unexpected state length: expected 3, got {}", z_i.len());
    }
    if z_i[0] != ofac_root {
        anyhow::bail!("OFAC root mismatch in proof state");
    }
    if z_i[1] != recipient {
        anyhow::bail!("recipient mismatch in proof state");
    }
    if z_i[2] != total_teleported {
        anyhow::bail!("total teleported mismatch in proof state");
    }

    log::info!("Innocence proof verified successfully");
    Ok(())
}

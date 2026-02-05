use std::fs;

use anyhow::{Context, Result};
use ark_bn254::Fr;
use serde::Deserialize;
use zkp::{
    nova::constants::EXCLUSION_TREE_HEIGHT,
    nova::innocence_nova::InnocenceExternalInputs,
    utils::convertion::b256_to_fr,
};

use crate::{CommonArgs, PoiGenerateArgs, PoiVerifyArgs};
use crate::commands::shared::parse_b256;
use crate::proof::innocence;

#[derive(Deserialize)]
struct TransferInput {
    from_address: String,
    value: String,
    secret: String,
}

#[derive(Deserialize)]
struct ExclusionProofInput {
    from_address: String,
    start: String,
    end: String,
    path: Vec<String>,
    position: u64,
}

fn parse_fr(hex_str: &str) -> Result<Fr> {
    let b = parse_b256(hex_str).map_err(|e| anyhow::anyhow!("{}", e))?;
    Ok(b256_to_fr(b))
}

pub async fn generate(common: &CommonArgs, args: &PoiGenerateArgs) -> Result<()> {
    let artifacts_dir = common
        .nova_artifacts_dir
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Nova artifacts directory must be specified"))?;

    let transfers_json = fs::read_to_string(&args.transfers_file)
        .with_context(|| format!("failed to read transfers file: {}", args.transfers_file.display()))?;
    let transfers: Vec<TransferInput> = serde_json::from_str(&transfers_json)
        .context("failed to parse transfers JSON")?;

    let exclusion_json = fs::read_to_string(&args.exclusion_proofs_file)
        .with_context(|| format!("failed to read exclusion proofs file: {}", args.exclusion_proofs_file.display()))?;
    let exclusion_proofs: Vec<ExclusionProofInput> = serde_json::from_str(&exclusion_json)
        .context("failed to parse exclusion proofs JSON")?;

    if transfers.len() != exclusion_proofs.len() {
        anyhow::bail!(
            "mismatched lengths: {} transfers vs {} exclusion proofs",
            transfers.len(),
            exclusion_proofs.len()
        );
    }

    let recipient = b256_to_fr(args.recipient);
    let ofac_root = b256_to_fr(args.ofac_root);

    let mut external_inputs = Vec::new();
    for (transfer, proof) in transfers.iter().zip(exclusion_proofs.iter()) {
        let from_address = parse_fr(&transfer.from_address)
            .context("failed to parse transfer from_address")?;
        let value = parse_fr(&transfer.value)
            .context("failed to parse transfer value")?;
        let secret = parse_fr(&transfer.secret)
            .context("failed to parse transfer secret")?;
        let start = parse_fr(&proof.start)
            .context("failed to parse exclusion proof start")?;
        let end = parse_fr(&proof.end)
            .context("failed to parse exclusion proof end")?;
        let gap_index = Fr::from(proof.position);

        let mut siblings = Vec::new();
        for (i, s) in proof.path.iter().enumerate() {
            siblings.push(
                parse_fr(s).with_context(|| format!("failed to parse sibling at index {}", i))?,
            );
        }
        let siblings: [Fr; EXCLUSION_TREE_HEIGHT] = siblings.try_into().map_err(|v: Vec<Fr>| {
            anyhow::anyhow!(
                "expected {} siblings, got {}",
                EXCLUSION_TREE_HEIGHT,
                v.len()
            )
        })?;

        // Verify from_address matches between transfer and exclusion proof
        let proof_from = parse_fr(&proof.from_address)
            .context("failed to parse exclusion proof from_address")?;
        if from_address != proof_from {
            anyhow::bail!(
                "from_address mismatch between transfer and exclusion proof"
            );
        }

        external_inputs.push(InnocenceExternalInputs::<Fr, EXCLUSION_TREE_HEIGHT> {
            is_dummy: false,
            from_address,
            value,
            secret,
            start,
            end,
            gap_index,
            siblings,
        });
    }

    let proof_bytes = innocence::generate_innocence_proof::<EXCLUSION_TREE_HEIGHT>(
        artifacts_dir,
        recipient,
        ofac_root,
        external_inputs,
    )?;

    fs::write(&args.output, &proof_bytes)
        .with_context(|| format!("failed to write proof to {}", args.output.display()))?;

    println!("Proof of innocence generated and written to {}", args.output.display());
    Ok(())
}

pub async fn verify(common: &CommonArgs, args: &PoiVerifyArgs) -> Result<()> {
    let artifacts_dir = common
        .nova_artifacts_dir
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("Nova artifacts directory must be specified"))?;

    let proof_bytes = fs::read(&args.proof)
        .with_context(|| format!("failed to read proof file: {}", args.proof.display()))?;

    let recipient = b256_to_fr(args.recipient);
    let total_teleported = b256_to_fr(args.total_teleported);
    let ofac_root = b256_to_fr(args.ofac_root);

    innocence::verify_innocence_proof::<EXCLUSION_TREE_HEIGHT>(
        artifacts_dir,
        &proof_bytes,
        recipient,
        total_teleported,
        ofac_root,
    )?;

    println!("Proof of innocence verified successfully");
    Ok(())
}

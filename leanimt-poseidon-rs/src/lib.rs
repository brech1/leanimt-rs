use ark_bn254::Fr;
use ark_ff::{BigInteger, PrimeField};
use leanimt_rs::*;
use light_poseidon::{Poseidon, PoseidonHasher};

// Leaf type
type PoseidonLeaf = [u8; 32];

/// Convert a field element to its byte representation
fn fr_to_bytes(fr: &Fr) -> PoseidonLeaf {
    let mut bytes = [0u8; 32];

    let fr_bytes = fr.into_bigint().to_bytes_le();
    bytes[..fr_bytes.len()].copy_from_slice(&fr_bytes);
    bytes
}

/// Convert bytes back to a field element
fn bytes_to_fr(bytes: &PoseidonLeaf) -> Fr {
    Fr::from_le_bytes_mod_order(bytes)
}

// Implement NodeHasher trait for PoseidonLeaf using Poseidon
pub struct PoseidonHasherImpl;

impl NodeHasher<PoseidonLeaf> for PoseidonHasherImpl {
    fn hash(nodes: &[PoseidonLeaf]) -> PoseidonLeaf {
        if nodes.len() != 2 {
            panic!("Poseidon expects exactly 2 inputs");
        }

        // Convert bytes to Fr elements for Poseidon
        let fr1 = bytes_to_fr(&nodes[0]);
        let fr2 = bytes_to_fr(&nodes[1]);

        // Hash using Poseidon
        let mut poseidon = Poseidon::<Fr>::new_circom(2).unwrap();
        let hash_fr = poseidon.hash(&[fr1, fr2]).unwrap();

        // Convert result back to bytes
        fr_to_bytes(&hash_fr)
    }
}

pub type PoseidonLeanIMT = LeanIMT<PoseidonLeaf, PoseidonHasherImpl>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_byte_conversion() {
        let fr = Fr::from(12345u64);
        let bytes = fr_to_bytes(&fr);
        let fr_back = bytes_to_fr(&bytes);
        assert_eq!(fr, fr_back);
    }

    #[test]
    fn test_hash() {
        let fr1 = Fr::from(1u64);
        let fr2 = Fr::from(2u64);
        let input1 = fr_to_bytes(&fr1);
        let input2 = fr_to_bytes(&fr2);

        let result = PoseidonHasherImpl::hash(&[input1, input2]);
        let result_fr = bytes_to_fr(&result);

        println!("Hash result: {:?}", result);
        assert_eq!(result, fr_to_bytes(&result_fr));
    }

    #[test]
    fn test_poseidon_leanimt() {
        // Create leaf values
        let fr1 = Fr::from(1u64);
        let fr2 = Fr::from(2u64);
        let fr3 = Fr::from(3u64);
        let fr4 = Fr::from(4u64);

        let leaf1 = fr_to_bytes(&fr1);
        let leaf2 = fr_to_bytes(&fr2);
        let leaf3 = fr_to_bytes(&fr3);
        let leaf4 = fr_to_bytes(&fr4);

        let leaves = vec![leaf1, leaf2, leaf3, leaf4];

        let tree = PoseidonLeanIMT::new(&leaves).unwrap();

        // Generate proof for index 2
        let proof = tree.generate_proof(2).unwrap();

        // Verify proof
        assert!(PoseidonLeanIMT::verify_proof(&proof));

        // Test single leaf tree
        let single_tree = PoseidonLeanIMT::new(&[leaf1]).unwrap();
        let single_proof = single_tree.generate_proof(0).unwrap();
        assert!(PoseidonLeanIMT::verify_proof(&single_proof));
    }
}

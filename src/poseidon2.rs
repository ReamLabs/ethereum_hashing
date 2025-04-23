use crate::HASH_LEN;
use zkhash::ark_ff::{BigInteger, PrimeField, ToConstraintField};
use zkhash::fields::bn256::FpBN256;
use zkhash::poseidon2::poseidon2::Poseidon2;
use zkhash::poseidon2::poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS;

/// Returns the digest of `input`.
pub fn hash(input: &[u8]) -> Vec<u8> {
    Poseidon2Hash::hash_to_bytes(input)
}

/// Hash function returning a fixed-size array (to save on allocations).

pub fn hash_fixed(input: &[u8]) -> [u8; HASH_LEN] {
    Poseidon2Hash::hash_to_fixed_bytes(input)
}

/// Compute the hash of two slices concatenated.
pub fn hash32_concat(h1: &[u8], h2: &[u8]) -> [u8; 32] {
    let input = vec![h1, h2].concat();
    Poseidon2Hash::hash_to_fixed_bytes(&input)
}

/// Poseidon2 hash with Bn254 Field.
struct Poseidon2Hash;

impl Poseidon2Hash {
    pub fn get_t() -> usize {
        let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS);
        poseidon2.get_t()
    }

    /// Basic hash function leverage poseidon2 hash from zkhash
    pub fn hash(fields: &[FpBN256]) -> Vec<FpBN256> {
        let mut hash_fields = vec![];
        let poseidon2 = Poseidon2::new(&POSEIDON2_BN256_PARAMS);
        let t = poseidon2.get_t();
        for chunk in fields.chunks_exact(t) {
            let perm = poseidon2.permutation(chunk);

            hash_fields.extend_from_slice(perm.as_slice());
        }
        hash_fields
    }

    pub fn hash_to_bytes(input: &[u8]) -> Vec<u8> {
        let fields: Vec<FpBN256> = input.to_field_elements().unwrap();

        let hash_fields = Self::hash(&fields);

        hash_fields
            .into_iter()
            .flat_map(|f| f.into_bigint().to_bytes_be())
            .collect::<Vec<u8>>()
    }

    pub fn hash_to_fixed_bytes(input: &[u8]) -> [u8; HASH_LEN] {
        let fields: Vec<FpBN256> = input.to_field_elements().unwrap();

        let hash_fields = Self::hash(&fields);

        let res = hash_fields.into_iter().sum::<FpBN256>();
        let bytes = res.into_bigint().to_bytes_be();
        bytes.as_slice().try_into().expect("Incorrect HASH_LEN")
    }

    pub fn hash_to_field(input: &[u8]) -> FpBN256 {
        let fields: Vec<FpBN256> = input.to_field_elements().unwrap();

        let hash_fields = Self::hash(&fields);

        let res = hash_fields.into_iter().sum::<FpBN256>();
        res
    }

    pub fn hash_field_to_bytes(fields: &[FpBN256]) -> Vec<u8> {
        let hash_fields = Self::hash(&fields);

        let res = hash_fields.iter().sum::<FpBN256>();
        res.into_bigint().to_bytes_be()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use zkhash::fields::utils::from_hex;

    #[test]
    fn test_poseidon_hash() {
        let mut input: Vec<FpBN256> = vec![];
        for i in 0..Poseidon2Hash::get_t() {
            input.push(FpBN256::from(i as u64));
        }
        let perm = Poseidon2Hash::hash(&input);
        assert_eq!(
            perm[0],
            from_hex("0x0bb61d24daca55eebcb1929a82650f328134334da98ea4f847f760054f4a3033")
        );
        assert_eq!(
            perm[1],
            from_hex("0x303b6f7c86d043bfcbcc80214f26a30277a15d3f74ca654992defe7ff8d03570")
        );
        assert_eq!(
            perm[2],
            from_hex("0x1ed25194542b12eef8617361c3ba7c52e660b145994427cc86296242cf766ec8")
        );
        println!("Success to test poseidon hash");
    }
}

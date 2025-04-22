use zkhash::ark_ff::{BigInteger, PrimeField, ToConstraintField};
use zkhash::fields::bn256::FpBN256;
use zkhash::poseidon2::poseidon2::Poseidon2;
use zkhash::poseidon2::poseidon2_instance_bn256::POSEIDON2_BN256_PARAMS;

pub struct Poseidon2Hash;

impl Poseidon2Hash {
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

    pub fn hash_bytes(input: &[u8]) -> Vec<u8> {
        let fields: Vec<FpBN256> = input.to_field_elements().unwrap();

        let hash_fields = Self::hash(&fields);

        let res = hash_fields.into_iter().sum::<FpBN256>();
        res.into_bigint().to_bytes_be()
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

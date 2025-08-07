
#[cfg(test)]
mod perf_tests {
    use ethereum_hashing::hash_fixed;
    use std::time::Instant;

    fn generate_input(size: usize) -> Vec<u8> {
        vec![42; size]
    }

    #[test]
    fn compare_hash_fixed_performance() {
        let input = generate_input(1024); 
        let iterations = 100_000;

        let _ = hash_fixed(&input);

        let start = Instant::now();
        for _ in 0..iterations {
            let _ = hash_fixed(&input);
        }
        let duration = start.elapsed();

        #[cfg(feature = "zkvm")]
        println!("zkvm hash_fixed() time for {iterations} iterations: {:?}", duration);

        #[cfg(not(feature = "zkvm"))]
        println!("dynamic hash_fixed() time for {iterations} iterations: {:?}", duration);
    }
}
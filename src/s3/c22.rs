use crate::mt19937::{Mt19937};
use std::time::{SystemTime, UNIX_EPOCH};
use rand::{self, Rng};

fn mt19937_first_output_to_seed(output: u64) -> u64 {

    let timestamp_curr = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time to exist");
    let timestamp = timestamp_curr.as_secs();

    for i in timestamp - 2000..(timestamp) {
        let mut mt = Mt19937::new(i);
        if mt.extract() == output {
            return i
        }
    }
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mt19937_brute_force() {
        let mut rng = rand::thread_rng();
        for _ in 0..100 {
            let timestamp_curr = SystemTime::now().duration_since(UNIX_EPOCH).expect("Time to exist");
            let timestamp = timestamp_curr.as_secs() - rng.gen_range(40, 1000);
            let mut mt = Mt19937::new(timestamp);
            assert_eq!(timestamp, mt19937_first_output_to_seed(mt.extract()))
        }
    }
}

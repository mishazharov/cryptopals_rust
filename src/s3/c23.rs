use crate::mt19937::{consts, Mt19937};
use rand::{self, Rng};

// This function is pretty messy
fn untemper(y1: u64) -> u64 {
    // Untemper
    // S1
    let mut yi = y1 ^ (y1 >> consts::L);

    // S2
    let mut l = yi & consts::LOWER_MASK;
    let mut r = yi & consts::UPPER_MASK;
    let mut h = ((l << consts::T) & consts::C) ^ r;
    yi = (h & consts::UPPER_MASK) ^ l;

    // S3
    l = yi & 0xFFFF; // Lower 16 bits are instantly known
    r = yi & !0xFFFF;
    h = ((l << consts::S) & consts::B) ^ r;
    // Lower 32 bits are known
    let mut yii = (h & !0xFFFF) ^ l;

    l = yii & consts::LOWER_MASK;
    r = yi & consts::UPPER_MASK;
    h = ((l << consts::S) & consts::B) ^ r;
    // Lower 48 bits are known
    yii = (h & consts::UPPER_MASK) ^ l;

    l = yii & 0xFFFFFFFFFFFF;
    r = yi & !0xFFFFFFFFFFFF;
    h = ((yii << consts::S) & consts::B) ^ r;
    yi = (h & !0xFFFFFFFFFFFF) ^ l;

    // S4
    let mut low_mask: u64 = (1 << 35) - 1;
    h = yi & !low_mask; // Top 29 bits are known
    r = yi & low_mask;
    l = ((yi >> consts::U) & consts::D) ^ r;
    yii = h ^ (l & low_mask);

    low_mask = (1 << 7) - 1;
    h = yii & !low_mask;
    r = yii & low_mask;
    l = ((yi >> consts::U) & consts::D) ^ r;
    yii = h ^ (l & low_mask);

    h = yii;
    l = (yi >> consts::U) & consts::D;
    yii = h ^ (l & low_mask);

    yii
}

fn clone_mt19937(mt: &mut Mt19937) -> Mt19937 {
    let mut state = [0; consts::N as usize];

    for i in 0..consts::N {
        state[i] = untemper(mt.extract());
    }

    Mt19937::from(state)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_clone_mt19937() {
        let mut prng = Mt19937::new(1654545);
        let mut rng = rand::thread_rng();

        for _ in 0..rng.gen_range(0, consts::N * 2 + 1) {
            prng.extract();
        }

        let mut new_prng: Mt19937 = clone_mt19937(&mut prng);

        for _ in 0..1000 {
            assert_eq!(prng.extract(), new_prng.extract());
        }
    }

    #[test]
    fn test_untemper() {
        let mut rng = rand::thread_rng();
        for _ in 0..1000 {
            let v: u64 = rng.gen();
            assert_eq!(untemper(Mt19937::temper(v)), v);
        }
    }
}

use rand::{self, Rng, distributions::Standard};

pub fn rand_len(len: usize) -> Vec<u8> {
    let rng = rand::thread_rng();
    let res: Vec<u8> = rng.sample_iter(Standard).take(len).collect();
    return res;
}

pub fn rand_len_range(low: usize, high: usize) -> Vec<u8> {
    let mut rng = rand::thread_rng();
    let size = rng.gen_range(low, high);
    let res: Vec<u8> = rng
        .sample_iter(Standard)
        .take(size)
        .collect();
    res
}

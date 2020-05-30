
// Implements 64 bit Mt19937 PRNG
// (https://en.wikipedia.org/wiki/Mersenne_Twister)

pub mod consts {
    pub const W: u64 = 64;
    pub const N: usize = 312;
    pub const M: u64 = 156;
    pub const R: u64 = 31;
    pub const A: u64 = 0xB5026F5AA96619E9;
    pub const U: u64 = 29;
    pub const D: u64 = 0x5555555555555555;
    pub const S: u64 = 17;
    pub const B: u64 = 0x71D67FFFEDA60000;
    pub const T: u64 = 37;
    pub const C: u64 = 0xFFF7EEE000000000;
    pub const L: u64 = 43;
    pub const F: u64 = 6364136223846793005;
    pub const LOWER_MASK: u64 = (1 << R) - 1;
    pub const UPPER_MASK: u64 = !LOWER_MASK;
}

pub struct Mt19937 {
    mt: [u64; consts::N as usize],
    index: usize
}

impl Mt19937 {
    pub fn new(seed: u64) -> Mt19937 {
        let mut res = Mt19937 {
            mt: [0; consts::N as usize],
            index: consts::N
        };

        res.mt[0] = seed;

        for i in 1..consts::N {
            res.mt[i] = (
                consts::F.wrapping_mul(
                    res.mt[i-1] ^ (res.mt[i-1] >> (consts::W-2))
                ) + i as u64
            ) as u64;
        }

        return res
    }

    fn twist(&mut self) {
        for i in 0..consts::N {
            let x = 
                (self.mt[i] & consts::UPPER_MASK) +
                (self.mt[(i+1) % consts::N] & consts::LOWER_MASK)
            ;

            let mut x_a = x >> 1;
            if x % 2 != 0 {
                x_a ^= consts::A;
            }

            self.mt[i] = self.mt[(i + consts::M as usize) % consts::N] ^ x_a;
        }

        self.index = 0;
    }

    pub fn temper(y1: u64) -> u64 {
        let mut y = y1 ^ ((y1 >> consts::U) & consts::D);
        y = y ^ ((y << consts::S) & consts::B);
        y = y ^ ((y << consts::T) & consts::C);
        return y ^ (y >> consts::L);
    }

    pub fn extract(&mut self) -> u64 {
        if self.index >= consts::N {
            self.twist();
        }

        let y = Mt19937::temper(self.mt[self.index]);
    
        self.index += 1;
        return y as u64
    }
}

impl From<[u64; consts::N as usize]> for Mt19937 {
    fn from(arr: [u64; consts::N as usize]) -> Self {
        Mt19937 {
            mt: arr,
            index: consts::N
        }
    }
}

// Tests generated with:
// #include <iostream>
// #include <random>

// int main()
// {
//     std::mt19937_64 generator(123);
    
//     for (int i = 0; i < 100; i++) {
//         std::cout << generator() << std::endl;
//     }
    
//     return 0;
// }

#[cfg(test)]
mod tests {
    use super::*;

    static TEST_ARR: &'static [u64] = &[
        5777523539921853504,
        10256004525803361771,
        17308305258728183101,
        13582745572890801790,
        3549292889148046380,
        3599698824668116388,
        17542111641530190888,
        5357772020071635406,
        15109402569541188053,
        9005878083635208240,
        4989597678449481749,
        10809250368948503438,
        994344248487496566,
        10299171316159037238,
        11797555524300478741,
        17981313440474340817,
        15698135450199770810,
        10956964208817395376,
        5995831931848466816,
        15448359660972415503,
        1862423402299864599,
        14801814343641537264,
        3311781361602019704,
        777734920438109132,
        10580938439913520740,
        16289987690178347391,
        13258668017375809563,
        5288091600886742778,
        25908348031121768,
        17344387309598287136,
        9504165594281223964,
        15741731246967608368,
        11485614883627857653,
        16808024499261395941,
        8242536403939624976,
        13183068567155725680,
        12740803632367211546,
        502531793125307200,
        1099586522124545387,
        7208300672617238698,
        4322313812028614562,
        221289985247795251,
        10010326911613079257,
        3308066933530881735,
        5020744043878119822,
        2725293300288995212,
        11740793681085073576,
        2140507163506247368,
        7681835731921478783,
        16050242555061706964,
        7347922011874963234,
        14382391377047202805,
        17342007485918078952,
        110910543544906162,
        10937585650047628936,
        11898831968258419493,
        17299760824468325088,
        12200901937990415313,
        7627493372067307580,
        16009335688382631274,
        9704891135349134353,
        15513228825447409701,
        10280767870337731882,
        2194631383138767249,
        7265412659824565019,
        6149204939291390482,
        2332437534371063327,
        17593083350677388402,
        6380739899631345379,
        10068981156002880521,
        8898847677530913977,
        10042188585005920550,
        4331973439114305434,
        2428101008952006082,
        14740448352331609581,
        11556818344531122134,
        8498449343713428532,
        5695980271928755860,
        5593880401288963562,
        7199139121099849225,
        5601187357705837907,
        6918392557402589837,
        13863159770020835671,
        11316526537369761785,
        12035259610614239593,
        14698824457564801533,
        8413180120839817471,
        1425967365239469352,
        2142139806994845388,
        5818256621045964532,
        11690385704471992310,
        3545208671095536135,
        5507108612721245323,
        10271988533132589081,
        16307230711328072849,
        7246932709923986577,
        14769179018881842643,
        2744667777884179956,
        15065828547078679204,
        12578658460393691383,
    ];

    #[test]
    fn test_mt19937() {
        let mut mt = Mt19937::new(123);

        for i in 0..TEST_ARR.len() {
            assert_eq!(mt.extract(), TEST_ARR[i]);
        }
    }
}

use crate::types::HashResult;
use crate::types::wrappers::{PaddingType, MessageBlock, ShaAlgorithm};
use crate::pre_processing::padding;
use crate::types::extended_nums::u160;
use crate::logical::operations::rot_l;
use crate::logical::functions::f;
use crate::constants::INITIAL_VALUES::SHA1_INITIAL_VALUES;
use crate::constants::SHA_CONSTANTS::SHA1_K;


pub fn hash_message(msg: &mut String, algorithm: ShaAlgorithm) -> HashResult {
    let pad_config = match algorithm {
        ShaAlgorithm::SHA1 | ShaAlgorithm::SHA224 | ShaAlgorithm::SHA256=> PaddingType::S512,
        ShaAlgorithm::SHA384 | ShaAlgorithm::SHA512 => PaddingType::S1024,
        ShaAlgorithm::SHA512T(_) => PaddingType::S1024,
    };
    let blocks = padding(msg, pad_config);
    let bin_result = match algorithm {
        ShaAlgorithm::SHA1 => sha_1(blocks),
        ShaAlgorithm::SHA512T(_) => {
            unimplemented!("SHA-512/t not implemented yet")
        }
        _ => panic!("Invalid algorithm for sha_1"),
    };
    bin_result
}

#[allow(dead_code)]
pub fn hash(message_blocks: Vec<MessageBlock>) -> HashResult {
    sha_1(message_blocks)
}

#[allow(non_snake_case)]
fn sha_1(message_blocks: Vec<MessageBlock>) -> HashResult {
    let mut H: [u32; 5] = SHA1_INITIAL_VALUES;
    for  block in message_blocks.iter() {
        //Prepare the schedule
        let mut schedule = [0; 80];
        if let MessageBlock::Block512(ref block) = block {
            for t in 0..16 {
                    schedule[t] = block[t];
            }
            for t in 16..80 {
                    schedule[t] = rot_l(schedule[t-3] ^ schedule[t-8] ^ schedule[t-14] ^ schedule[t-16], 1);
            }
            fn k(t: u8) -> u32 {
                const K: [u32; 4] = SHA1_K;
                match t {
                    0..=19 => K[0],
                    20..=39 => K[1],
                    40..=59 => K[2],
                    60..=79 => K[3],
                    _ => panic!("Invalid value for t"),
                }
            }
            let mut a = H[0];
            let mut b = H[1];
            let mut c = H[2];
            let mut d = H[3];
            let mut e = H[4];
            for t in 0..80 {
                let temp: u32 = rot_l(a, 5)
                    .wrapping_add(f(t, b, c, d))
                    .wrapping_add(e)
                    .wrapping_add(k(t))
                    .wrapping_add(schedule[t as usize]);
                e = d;
                d = c;
                c = rot_l(b, 30);
                b = a;
                a = temp;
            }
            H[0] = H[0].wrapping_add(a);
            H[1] = H[1].wrapping_add(b);
            H[2] = H[2].wrapping_add(c);
            H[3] = H[3].wrapping_add(d);
            H[4] = H[4].wrapping_add(e);
        } else {
            panic!("Invalid block for sha_1");
        }
    }
    HashResult::U160(u160::new(H[0], H[1], H[2], H[3], H[4]))
}

use crate::types::HashResult;
use crate::types::wrappers::{PaddingType, MessageBlock, ShaAlgorithm};
use crate::pre_processing::padding;
use crate::types::extended_nums::{u160, u224, u256, u384, u512};
use crate::logical::operations::{rot_l, ch, maj};
use crate::logical::functions::{f, sigma_0, sigma_1, csigma_0, csigma_1};
use crate::constants::INITIAL_VALUES::{SHA1_INITIAL_VALUES, SHA224_INITIAL_VALUES, SHA256_INITIAL_VALUES, SHA384_INITIAL_VALUES, SHA512_INITIAL_VALUES};
use crate::constants::SHA_CONSTANTS::{SHA1_K, SHA256_K, SHA512_K};


pub fn hash_message(msg: &mut String, algorithm: ShaAlgorithm) -> HashResult {
    let pad_config = match algorithm {
        ShaAlgorithm::SHA1 | ShaAlgorithm::SHA224 | ShaAlgorithm::SHA256=> PaddingType::S512,
        ShaAlgorithm::SHA384 | ShaAlgorithm::SHA512 => PaddingType::S1024,
        ShaAlgorithm::SHA512T(_) => PaddingType::S1024,
    };
    let blocks = padding(msg, pad_config);
    let bin_result = match algorithm {
        ShaAlgorithm::SHA1 => sha_1(blocks),
        ShaAlgorithm::SHA224 => sha_2_small(blocks, ShaAlgorithm::SHA224),
        ShaAlgorithm::SHA256 => sha_2_small(blocks, ShaAlgorithm::SHA256),
        ShaAlgorithm::SHA384 => sha_2_large(blocks, ShaAlgorithm::SHA384),
        ShaAlgorithm::SHA512 => sha_2_large(blocks, ShaAlgorithm::SHA512),
        ShaAlgorithm::SHA512T(_) => {
            unimplemented!("SHA-512/t not implemented yet")
        }
    };
    bin_result
}


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


fn sha_2_small(message_blocks: Vec<MessageBlock>, algorithm: ShaAlgorithm) -> HashResult {
    // Initialize the hash values
    let mut H = {
        match algorithm {
            ShaAlgorithm::SHA224 => SHA224_INITIAL_VALUES,
            ShaAlgorithm::SHA256 => SHA256_INITIAL_VALUES,
            _ => panic!("Invalid algorithm for sha_2"),
        }
    };
    const K: [u32; 64] = SHA256_K;

    // Iterate over the message blocks until n-block
    for block in message_blocks.iter() {
        if let MessageBlock::Block512(ref block) = block {

            //Prepare the schedule
            let mut schedule  = [0; 64];
            for t in 0..16 {
            schedule[t] = block[t];
            }
            for t in 16..64 {
                schedule[t] = {
                    sigma_1(schedule[t-2])
                        .wrapping_add(schedule[t-7])
                        .wrapping_add(sigma_0(schedule[t-15]))
                        .wrapping_add(schedule[t-16])
                };
            }

            //Initialize the working variables
            let mut a = H[0];
            let mut b = H[1];
            let mut c = H[2];
            let mut d = H[3];
            let mut e = H[4];
            let mut f = H[5];
            let mut g = H[6];
            let mut h = H[7];

            //Variables rotation with compresion function
            for t in 0..64 {
                let temp_1: u32 = h
                    .wrapping_add(csigma_1(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(K[t])
                    .wrapping_add(schedule[t as usize]);
                let temp_2: u32 = csigma_0(a).wrapping_add(maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp_1);
                d = c;
                c = b;
                b = a;
                a = temp_1.wrapping_add(temp_2);
            }

            //Add the compressed chunk to the current hash value
            H[0] = H[0].wrapping_add(a);
            H[1] = H[1].wrapping_add(b);
            H[2] = H[2].wrapping_add(c);
            H[3] = H[3].wrapping_add(d);
            H[4] = H[4].wrapping_add(e);
            H[5] = H[5].wrapping_add(f);
            H[6] = H[6].wrapping_add(g);
            H[7] = H[7].wrapping_add(h);
        } else {
            panic!("Invalid block for sha_512");
        }
    }

    //Return the hash
    match algorithm {
        ShaAlgorithm::SHA224 => HashResult::U224(u224::new(H[0], H[1], H[2], H[3], H[4], H[5], H[6])),
        ShaAlgorithm::SHA256 => HashResult::U256(u256::new(H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7])),
        _ => panic!("Invalid algorithm for sha_2_small"),
    }
}

pub fn sha_2_large(message_blocks: Vec<MessageBlock>, algorithm: ShaAlgorithm) -> HashResult {
    // Initialize the hash values
    let mut H = {
        match algorithm {
            ShaAlgorithm::SHA384 => SHA384_INITIAL_VALUES,
            ShaAlgorithm::SHA512 => SHA512_INITIAL_VALUES,
            _ => panic!("Invalid algorithm for sha_2"),
        }
    };
    const K: [u64; 80] = SHA512_K;

    // Iterate over the message blocks until n-block
    for block in message_blocks.iter() {
        if let MessageBlock::Block1024(ref block) = block {

            //Prepare the schedule
            let mut schedule  = [0; 80];
            for t in 0..16 {
            schedule[t] = block[t];
            }
            for t in 16..80 {
                schedule[t] = {
                    sigma_1(schedule[t-2])
                        .wrapping_add(schedule[t-7])
                        .wrapping_add(sigma_0(schedule[t-15]))
                        .wrapping_add(schedule[t-16])
                };
            }

            //Initialize the working variables
            let mut a = H[0];
            let mut b = H[1];
            let mut c = H[2];
            let mut d = H[3];
            let mut e = H[4];
            let mut f = H[5];
            let mut g = H[6];
            let mut h = H[7];

            //Variables rotation with compresion function
            for t in 0..64 {
                let temp_1  = h
                    .wrapping_add(csigma_1(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(K[t])
                    .wrapping_add(schedule[t as usize]);
                let temp_2  = csigma_0(a).wrapping_add(maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp_1);
                d = c;
                c = b;
                b = a;
                a = temp_1.wrapping_add(temp_2);
            }

            //Add the compressed chunk to the current hash value
            H[0] = H[0].wrapping_add(a);
            H[1] = H[1].wrapping_add(b);
            H[2] = H[2].wrapping_add(c);
            H[3] = H[3].wrapping_add(d);
            H[4] = H[4].wrapping_add(e);
            H[5] = H[5].wrapping_add(f);
            H[6] = H[6].wrapping_add(g);
            H[7] = H[7].wrapping_add(h);
        } else {
            panic!("Invalid block for sha_512");
        }
    }

    //Return the hash
    match algorithm {
        ShaAlgorithm::SHA384 => HashResult::U384(u384::new(H[0], H[1], H[2], H[3], H[4], H[5])),
        ShaAlgorithm::SHA512 => HashResult::U512(u512::new(H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7])),
        _ => panic!("Invalid algorithm for sha_2_small"),
    }
}

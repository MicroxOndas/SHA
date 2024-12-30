use crate::types::HashResult;
use crate::types::wrappers::{PaddingType, MessageBlock, ShaAlgorithm};
use crate::types::extended_nums::{u160, u224, u256, u384, u512};
use crate::logical::operations::{rot_l, ch, maj};
use crate::logical::functions::{f, sigma_0, sigma_1, csigma_0, csigma_1};
use crate::constants::INITIAL_VALUES::{SHA1_INITIAL_VALUES, SHA224_INITIAL_VALUES, SHA256_INITIAL_VALUES, SHA384_INITIAL_VALUES, SHA512_INITIAL_VALUES};
use crate::constants::SHA_CONSTANTS::{SHA1_K, SHA224_K, SHA256_K, SHA384_K, SHA512_K};

pub fn hash_message(msg: &mut String, algorithm: ShaAlgorithm) -> HashResult {
    let msg = msg;
    let pad_config = match algorithm {
        ShaAlgorithm::SHA1 => PaddingType::S512,
        ShaAlgorithm::SHA224 => PaddingType::S512,
        ShaAlgorithm::SHA256 => PaddingType::S512,
        ShaAlgorithm::SHA384 => PaddingType::S1024,
        ShaAlgorithm::SHA512 => PaddingType::S1024,
        ShaAlgorithm::SHA512T(_) => PaddingType::S1024,
    };
    let blocks = padding(msg, pad_config);
    let bin_result = match algorithm {
        ShaAlgorithm::SHA1 => sha_1(blocks),
        ShaAlgorithm::SHA224 => sha_224(blocks),
        ShaAlgorithm::SHA256 => sha_256(blocks),
        ShaAlgorithm::SHA384 => sha_384(blocks),
        ShaAlgorithm::SHA512 => sha_512(blocks),
        ShaAlgorithm::SHA512T(_) => {
            unimplemented!()
        },
        _ => panic!("Invalid algorithm for hash_message"),
    };
    bin_result
}

fn padding(msg: &mut String, pad_config: PaddingType) -> Vec<MessageBlock> {
    let original_len = msg.len() * 8;
    let k: usize = {
        match pad_config {
            PaddingType::S512 => {
                ((448 + 512) - ((original_len + 1) % 512)) % 512
            },
            PaddingType::S1024 => {
                ((896 + 1024) - ((original_len + 1) % 1024)) % 1024
            },
        }
    };

    // Append a single '1' bit followed by k '0' bits
    let mut bin_chars: Vec<u8> = msg.chars().map(|c| c as u8).collect();
    let ini = if k%8==0 { 1 } else { 0 };
    bin_chars.push(0b10000000);
    for _ in ini..(k/8) {
        bin_chars.push(0b00000000);
    }

    // Append the length of the original message as a 64 or 128-bit binary number
    match pad_config {
        PaddingType::S512 => {
            let length_bytes: [u8; 8] = (original_len as u64).to_be_bytes();
            bin_chars.extend_from_slice(&length_bytes);
        },
        PaddingType::S1024 => {
            let length_bytes: [u8; 16] = (original_len as u128).to_be_bytes();
            bin_chars.extend_from_slice(&length_bytes);
        },
    }

    let mut result: Vec<MessageBlock> = 
        { 
            let n = match pad_config {
                    PaddingType::S512 => (bin_chars.len() * 8) / 512,
                    PaddingType::S1024 => (bin_chars.len() * 8) / 1024,
                };
            let mut result: Vec<MessageBlock> = Vec::with_capacity(n);
            for _ in 0..n {
                match pad_config {
                    PaddingType::S512 => result.push(MessageBlock::Block512([0; 16])),
                    PaddingType::S1024 => result.push(MessageBlock::Block1024([0; 16])),
                }
            }
            result
        };
    

    // Divide bin_chars into chunks and populate the MessageBlocks
    let chunks = bin_chars.chunks(bin_chars.len()/result.len());
    for (i, chunk) in chunks.enumerate() {
        result[i] = {
            match pad_config {
                PaddingType::S512 => {
                    let mut block: [u32; 16] = [0; 16];
                    for (j, subchunk) in chunk.chunks(4).enumerate() {
                        if subchunk.len() == 4 {
                            block[j] = u32::from_be_bytes([subchunk[0], subchunk[1], subchunk[2], subchunk[3]]);
                        } else {
                            panic!("Invalid chunk size");
                        }
                    }
                    MessageBlock::Block512(block)
                },
                PaddingType::S1024 => {
                    let mut block: [u64; 16]  = [0; 16];
                    for (j, subchunk) in chunk.chunks(8).enumerate() {
                        if subchunk.len() == 8 {
                            block[j] = u64::from_be_bytes([subchunk[0], subchunk[1], subchunk[2], subchunk[3],
                                                            subchunk[4], subchunk[5], subchunk[6], subchunk[7]]);
                        } else {
                            panic!("Invalid chunk size");
                        }
                    }
                    MessageBlock::Block1024(block)
                },
            }
        };
    };
    result
}

pub fn sha_1(message_blocks: Vec<MessageBlock>) -> HashResult {
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

fn sha_224(message_blocks: Vec<MessageBlock>) -> HashResult {
    let mut H = SHA224_INITIAL_VALUES;
    const K: [u32; 64] = SHA224_K;
    for  block in message_blocks.iter() {
        //Prepare the schedule
        let mut schedule: Vec<u32> = vec![0; 64];
        if let MessageBlock::Block512(ref block) = block {
            for t in 0..64 {
                if t < 16 {
                    let word = block.iter().cloned().collect::<Vec<u32>>()[t];
                    schedule[t] = word.clone();
                } else {
                    schedule[t] = {
                        sigma_1(schedule[t-2])
                            .wrapping_add(schedule[t-7])
                            .wrapping_add(sigma_0(schedule[t-15]))
                            .wrapping_add(schedule[t-16])
                    };
                }
            }
            let mut a = H[0];
            let mut b = H[1];
            let mut c = H[2];
            let mut d = H[3];
            let mut e = H[4];
            let mut f = H[5];
            let mut g = H[6];
            let mut h = H[7];
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
            H[0] = H[0].wrapping_add(a);
            H[1] = H[1].wrapping_add(b);
            H[2] = H[2].wrapping_add(c);
            H[3] = H[3].wrapping_add(d);
            H[4] = H[4].wrapping_add(e);
            H[5] = H[5].wrapping_add(f);
            H[6] = H[6].wrapping_add(g);
            H[7] = H[7].wrapping_add(h);
        } else {
            panic!("Invalid block for sha_1");
        }
    }
    HashResult::U224(u224::new(H[0], H[1], H[2], H[3], H[4], H[5], H[6]))
}

fn sha_256(message_blocks: Vec<MessageBlock>) -> HashResult {
    let mut H = SHA256_INITIAL_VALUES;
    const K: [u32; 64] = SHA256_K;
    for  block in message_blocks.iter() {
        //Prepare the schedule
        let mut schedule = [0; 64];
        if let MessageBlock::Block512(ref block) = block {
            for t in 0..64 {
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
            let mut a = H[0];
            let mut b = H[1];
            let mut c = H[2];
            let mut d = H[3];
            let mut e = H[4];
            let mut f = H[5];
            let mut g = H[6];
            let mut h = H[7];
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
            H[0] = H[0].wrapping_add(a);
            H[1] = H[1].wrapping_add(b);
            H[2] = H[2].wrapping_add(c);
            H[3] = H[3].wrapping_add(d);
            H[4] = H[4].wrapping_add(e);
            H[5] = H[5].wrapping_add(f);
            H[6] = H[6].wrapping_add(g);
            H[7] = H[7].wrapping_add(h);
        } else {
            panic!("Invalid block for sha_1");
        }
    }
    HashResult::U256(u256::new(H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]))
}

fn sha_384(message_blocks: Vec<MessageBlock>) -> HashResult {
    let mut H = SHA384_INITIAL_VALUES;
    const K: [u64; 80] = SHA384_K;
    for  block in message_blocks.iter() {
        //Prepare the schedule
        let mut schedule  = [0; 80];
        if let MessageBlock::Block1024(ref block) = block {
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
            let mut a = H[0];
            let mut b = H[1];
            let mut c = H[2];
            let mut d = H[3];
            let mut e = H[4];
            let mut f = H[5];
            let mut g = H[6];
            let mut h = H[7];
            for t in 0..80 {
                let temp_1: u64 = h
                    .wrapping_add(csigma_1(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(K[t])
                    .wrapping_add(schedule[t as usize]);
                let temp_2: u64 = csigma_0(a).wrapping_add(maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp_1);
                d = c;
                c = b;
                b = a;
                a = temp_1.wrapping_add(temp_2);
            }
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
    HashResult::U384(u384::new(H[0], H[1], H[2], H[3], H[4], H[5]))
}

fn sha_512(message_blocks: Vec<MessageBlock>) -> HashResult {
    let mut H = SHA512_INITIAL_VALUES;
    const K: [u64; 80] = SHA512_K;
    for  block in message_blocks.iter() {
        //Prepare the schedule
        let mut schedule  = [0; 80];
        if let MessageBlock::Block1024(ref block) = block {
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
            let mut a = H[0];
            let mut b = H[1];
            let mut c = H[2];
            let mut d = H[3];
            let mut e = H[4];
            let mut f = H[5];
            let mut g = H[6];
            let mut h = H[7];
            for t in 0..80 {
                let temp_1: u64 = h
                    .wrapping_add(csigma_1(e))
                    .wrapping_add(ch(e, f, g))
                    .wrapping_add(K[t])
                    .wrapping_add(schedule[t as usize]);
                let temp_2: u64 = csigma_0(a).wrapping_add(maj(a, b, c));
                h = g;
                g = f;
                f = e;
                e = d.wrapping_add(temp_1);
                d = c;
                c = b;
                b = a;
                a = temp_1.wrapping_add(temp_2);
            }
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
    HashResult::U512(u512::new(H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7]))
}

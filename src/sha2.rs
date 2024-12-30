use crate::types::HashResult;
use crate::types::wrappers::{PaddingType, MessageBlock, ShaAlgorithm};
use crate::pre_processing::padding;
use crate::types::extended_nums::{u224, u256, u384, u512};
use crate::logical::operations::{ch, maj};
use crate::logical::functions::{sigma_0, sigma_1, csigma_0, csigma_1};
use crate::constants::INITIAL_VALUES::{InitialValues, Constants, SHA224_INITIAL_VALUES, SHA256_INITIAL_VALUES, SHA384_INITIAL_VALUES, SHA512_INITIAL_VALUES};
use crate::constants::SHA_CONSTANTS::{SHA224_K, SHA256_K, SHA384_K, SHA512_K};

pub fn hash_message(msg: &mut String, algorithm: ShaAlgorithm) -> HashResult {
    let pad_config = match algorithm {
        ShaAlgorithm::SHA1 | ShaAlgorithm::SHA224 | ShaAlgorithm::SHA256=> PaddingType::S512,
        ShaAlgorithm::SHA384 | ShaAlgorithm::SHA512 => PaddingType::S1024,
        ShaAlgorithm::SHA512T(_) => PaddingType::S1024,
    };
    let blocks = padding(msg, pad_config);
    let bin_result = match algorithm {
        ShaAlgorithm::SHA1 => panic!("SHA-1 not admited sha2.rs"),
        ShaAlgorithm::SHA224 => hash(blocks, ShaAlgorithm::SHA224),
        ShaAlgorithm::SHA256 => hash(blocks, ShaAlgorithm::SHA256),
        ShaAlgorithm::SHA384 => hash(blocks, ShaAlgorithm::SHA384),
        ShaAlgorithm::SHA512 => hash(blocks, ShaAlgorithm::SHA512),
        ShaAlgorithm::SHA512T(len) => {
            hash(blocks, ShaAlgorithm::SHA512T(len))
        }
    };
    bin_result
}

#[allow(non_snake_case)]
pub fn hash(message_blocks: Vec<MessageBlock>, algorithm: ShaAlgorithm) -> HashResult {
    let H = obtain_initial_values(&algorithm);
    let K = obtain_constants(&algorithm);

    match algorithm {
        ShaAlgorithm::SHA224 | ShaAlgorithm::SHA256 => sha_2_small(message_blocks, algorithm, H, K),
        ShaAlgorithm::SHA384 | ShaAlgorithm::SHA512 => sha_2_large(message_blocks, algorithm, H, K),
        ShaAlgorithm::SHA512T(t) => {
            if t < 1 || t > 512 || t % 8 != 0 {
                panic!("Invalid length for SHA-512/t; must be a multiple of 8 and between 1 and 512");
            }
        
            // Initialize H with the modified initial values
            let mut H = crate::constants::INITIAL_VALUES::SHA512_INITIAL_VALUES;
            for value in H.iter_mut() {
                *value ^= 0xa5a5a5a5a5a5a5a5; // XOR with the constant
            }
        
            // Prepare the seed "SHA-512/{len}"
            let seed = &mut format!("SHA-512/{}", t);
        
            // Hash the seed using SHA-512 with the modified H as the initial state
            let seed_blocks = padding(seed, PaddingType::S1024);
            let seed_hash = sha_2_large(seed_blocks, ShaAlgorithm::SHA512, InitialValues::Large(H),Constants::Large(SHA512_K));

            // Use the result of the seed hash as the initial values for the actual message hash
            let H = match seed_hash {
                HashResult::U512(result) => result.get_values(),
                _ => panic!("Invalid result for SHA-512/t seed hash"),
            };

            // Perform the actual message hash with the new initial values
            let result: HashResult = sha_2_large(message_blocks, algorithm, InitialValues::Large(H), K);
            match result {
                HashResult::U512(u512) => {
                    let values = u512.get_values();
                    let mut result_vec = Vec::new();
                    for &value in values.iter() {
                        result_vec.extend_from_slice(&value.to_be_bytes());
                    }
                    result_vec.truncate(t as usize / 8);
                    HashResult::U512T(result_vec)
                },
                _ => panic!("Invalid result for SHA-512/t"),
            }
        }
        _ => panic!("Invalid algorithm for sha_2"),
    }
}



fn obtain_constants(algorithm: &ShaAlgorithm) -> Constants {
    match algorithm {
        ShaAlgorithm::SHA224 => Constants::Small(SHA224_K),
        ShaAlgorithm::SHA256 => Constants::Small(SHA256_K),
        ShaAlgorithm::SHA384 => Constants::Large(SHA384_K),
        ShaAlgorithm::SHA512 => Constants::Large(SHA512_K),
        ShaAlgorithm::SHA512T(_) => Constants::Large(SHA512_K),
        _ => panic!("Invalid algorithm for sha_2"),
    }
}

#[allow(non_snake_case)]
fn obtain_initial_values(algorithm: &ShaAlgorithm) -> InitialValues {
    // Initialize the hash values
    match algorithm {
        ShaAlgorithm::SHA224 => InitialValues::Small(SHA224_INITIAL_VALUES),
        ShaAlgorithm::SHA256 => InitialValues::Small(SHA256_INITIAL_VALUES),
        ShaAlgorithm::SHA384 => InitialValues::Large(SHA384_INITIAL_VALUES),
        ShaAlgorithm::SHA512 => InitialValues::Large(SHA512_INITIAL_VALUES),
        ShaAlgorithm::SHA512T(len) => {
            let mut H = SHA512_INITIAL_VALUES;
            for value in H.iter_mut() {
                *value = *value ^ 0xa5a5a5a5a5a5a5a5;
            }
            let seed = &mut format!("SHA-512/{}", len);
            let compute = sha_2_large(padding(seed, PaddingType::S1024), ShaAlgorithm::SHA512, InitialValues::Large(H), Constants::Large(SHA512_K));
            match compute {
                HashResult::U512(result) => {
                    let values = result.get_values();
                    InitialValues::Large(values)
                },
                _ => panic!("Invalid result for SHA-512/t"),
            }
        },
        _ => panic!("Invalid algorithm for sha_2"),
    }
}

#[allow(non_snake_case)]
fn sha_2_small(message_blocks: Vec<MessageBlock>, algorithm: ShaAlgorithm, H: InitialValues, K: Constants) -> HashResult {
        
    let mut H = match H {
        InitialValues::Small(values) => values,
        InitialValues::Large(_) => panic!("Invalid initial values for sha_2_small"),
    };
    let K  = match K {
        Constants::Small(values) => values,
        Constants::Large(_) => panic!("Invalid constants for sha_2_large"),
    };
        
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

#[allow(non_snake_case)]
fn sha_2_large(message_blocks: Vec<MessageBlock>, algorithm: ShaAlgorithm, H: InitialValues, K: Constants) -> HashResult {

    let mut H = match H {
        InitialValues::Small(_) => panic!("Invalid initial values for sha_2_large"),
        InitialValues::Large(values) => values,
    };
    let K  = match K {
        Constants::Small(_) => panic!("Invalid constants for sha_2_large"),
        Constants::Large(values) => values,
    };
        
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
    
        // Return the hash
        match algorithm {
            ShaAlgorithm::SHA384 => HashResult::U384(u384::new(H[0], H[1], H[2], H[3], H[4], H[5])),
            ShaAlgorithm::SHA512 | ShaAlgorithm::SHA512T(_) => HashResult::U512(u512::new(H[0], H[1], H[2], H[3], H[4], H[5], H[6], H[7])),
            _ => panic!("Invalid algorithm for sha_2_large"),
        }
}
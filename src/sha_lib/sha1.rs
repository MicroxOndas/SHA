use core::result::Result;
use crate::sha_lib::err_handling::ShaError;
use crate::types::HashResult;
use crate::types::wrappers::{PaddingType, MessageBlock, ShaAlgorithm};
use crate::sha_lib::pre_processing::padding;
use crate::sha_lib::types::extended_nums::u160;
use crate::sha_lib::logic::operations::rot_l;
use crate::sha_lib::logic::functions::f;
use crate::sha_lib::constants::INITIAL_VALUES::SHA1_INITIAL_VALUES;
use crate::sha_lib::constants::SHA_CONSTANTS::SHA1_K;


pub fn hash_message(msg: &str, algorithm: &ShaAlgorithm) -> Result<HashResult,ShaError> {
    let pad_config = match algorithm {
        ShaAlgorithm::SHA1 => PaddingType::S512,
        _ => return Err(ShaError::InvalidAlgorithm),
    };
    let blocks = padding(msg, pad_config);
    let blocks = match blocks {
        Ok(blocks) => blocks,
        Err(e) => return Err(e),
    };
    let bin_result = match algorithm {
        ShaAlgorithm::SHA1 => hash(&blocks),
        _ => return Err(ShaError::InvalidAlgorithm),
    };
    bin_result
}

#[allow(dead_code)]
pub fn hash(message_blocks: &Vec<MessageBlock>) -> Result<HashResult, ShaError> {
    let result = sha_1(message_blocks);
    match result {
        Ok(hash) => Ok(hash),
        Err(e) => Err(e),
    }
}

#[allow(non_snake_case)]
fn sha_1(message_blocks: &Vec<MessageBlock>) -> Result<HashResult, ShaError> {
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
            fn k(t: u8) -> Result<u32, ShaError> {
                const K: [u32; 4] = SHA1_K;
                let ret = match t {
                    0..=19 => K[0],
                    20..=39 => K[1],
                    40..=59 => K[2],
                    60..=79 => K[3],
                    _ => Err(ShaError::CustomError("Invalid value for t".to_string()))?,
                };
                Ok(ret)
            }
            let mut a = H[0];
            let mut b = H[1];
            let mut c = H[2];
            let mut d = H[3];
            let mut e = H[4];
            for t in 0..80 {
                let temp: u32 = rot_l(a, 5)
                    .wrapping_add(match f(t, b, c, d){
                        Ok(val) => val,
                        Err(e) => Err(e)?,
                    })
                    .wrapping_add(e)
                    .wrapping_add(match k(t) {
                        Ok(val) => val,
                        Err(e) => Err(e)?,
                    })
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
            return Err(ShaError::InvalidPadding);
        }
    }
    Ok(HashResult::U160(u160::new(H[0], H[1], H[2], H[3], H[4])))
}

use crate::types::wrappers::{MessageBlock, PaddingType};

pub fn padding(msg: &mut String, pad_config: PaddingType) -> Vec<MessageBlock> {
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


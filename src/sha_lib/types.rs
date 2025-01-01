
pub mod wrappers {

    pub enum PaddingType {
        S512,
        S1024,
    }
    
    #[derive(Debug)]
    pub enum MessageBlock {
        Block512([u32; 16]), // 16 palabras de 32 bits (512 bits en total)
        Block1024([u64; 16]), // 16 palabras de 64 bits (1024 bits en total)
    }


    pub enum ShaAlgorithm {
        SHA1,
        SHA224,
        SHA256,
        SHA384,
        SHA512,
        SHA512T(u16)
    }
    
}

#[derive(Debug)]
#[allow(dead_code)]
pub enum HashResult {
    U160(extended_nums::u160),
    U224(extended_nums::u224),
    U256(extended_nums::u256),
    U384(extended_nums::u384),
    U512(extended_nums::u512),
    U512T(Vec<u8>),
}

impl HashResult {
    pub fn get_values(&self) -> Vec<u8> {
        match self {
            HashResult::U160(u160) => {
                let mut result: Vec<u8> = Vec::new();
                for i in u160.get_values().iter() {
                    result.extend_from_slice(&i.to_be_bytes());
                }
                result
            },
            HashResult::U224(u224) => {
                let mut result: Vec<u8> = Vec::new();
                for i in u224.get_values().iter() {
                    result.extend_from_slice(&i.to_be_bytes());
                }
                result
            },
            HashResult::U256(u256) => {
                let mut result: Vec<u8> = Vec::new();
                for i in u256.get_values().iter() {
                    result.extend_from_slice(&i.to_be_bytes());
                }
                result
            },
            HashResult::U384(u384) => {
                let mut result: Vec<u8> = Vec::new();
                for i in u384.get_values().iter() {
                    result.extend_from_slice(&i.to_be_bytes());
                }
                result
            },
            HashResult::U512(u512) => {
                let mut result: Vec<u8> = Vec::new();
                for i in u512.get_values().iter() {
                    result.extend_from_slice(&i.to_be_bytes());
                }
                result
            },
            HashResult::U512T(u512t) => {
                u512t.clone()
            },
        }
    }
}



#[allow(dead_code)]
#[allow(non_camel_case_types)]
pub mod extended_nums {

    #[derive(Debug)]
    pub struct u160 {
        a: u32,
        b: u32,
        c: u32,
        d: u32,
        e: u32,
    }
    
    impl u160 {
        pub fn new(a: u32, b: u32, c: u32, d: u32, e: u32) -> u160 {
            u160 { a, b, c, d, e }
        }

        pub fn get_values(&self) -> [u32; 5] {
            [self.a, self.b, self.c, self.d, self.e]
        }
    }
    
    #[derive(Debug)]
    
    pub struct u224 {
        a: u32,
        b: u32,
        c: u32,
        d: u32,
        e: u32,
        f: u32,
        g: u32,
    }

    impl u224 {
        pub fn new(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32, g: u32) -> u224 {
            u224 { a, b, c, d, e, f, g }
        }

        pub fn get_values(&self) -> [u32; 7] {
            [self.a, self.b, self.c, self.d, self.e, self.f, self.g]
        }
    }
    
    #[derive(Debug)]
    pub struct u256 {
        a: u32,
        b: u32,
        c: u32,
        d: u32,
        e: u32,
        f: u32,
        g: u32,
        h: u32,
    }

    impl u256 {
        pub fn new(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32, g: u32, h: u32) -> u256 {
            u256 { a, b, c, d, e, f, g, h }
        }
        
        pub fn get_values(&self) -> [u32; 8] {
            [self.a, self.b, self.c, self.d, self.e, self.f, self.g, self.h]
        }
    }
    
    #[derive(Debug)]
    pub struct u384 {
        a: u64,
        b: u64,
        c: u64,
        d: u64,
        e: u64,
        f: u64,
    }

    impl u384 {
        pub fn new(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64) -> u384 {
            u384 { a, b, c, d, e, f }
        }

        pub fn get_values(&self) -> [u64; 6] {
            [self.a, self.b, self.c, self.d, self.e, self.f]
        }
    }
    
    #[derive(Debug)]
    pub struct u512 {
        a: u64,
        b: u64,
        c: u64,
        d: u64,
        e: u64,
        f: u64,
        g: u64,
        h: u64,
    }

    impl u512 {
        pub fn new(a: u64, b: u64, c: u64, d: u64, e: u64, f: u64, g: u64, h: u64) -> u512 {
            u512 { a, b, c, d, e, f, g, h }
        }

        pub fn get_values(&self) -> [u64; 8] {
            [self.a, self.b, self.c, self.d, self.e, self.f, self.g, self.h]
        }
    }
}
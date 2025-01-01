pub mod operations {
        
    pub fn ch<T: 
    Copy + 
    std::ops::BitAnd<Output = T> + 
    std::ops::Not<Output = T> + 
    std::ops::BitXor<Output = T>
    >
    (x: T, y: T, z: T) -> T {
        (x & y) ^ (!x & z)
    }

    pub fn maj<T:
        Copy + 
        std::ops::BitAnd<Output = T> + 
        std::ops::BitXor<Output = T>
        >
    (x: T, y: T, z: T) -> T {
        (x & y) ^ (x & z) ^ (y & z)
    }

    pub fn parity<T:
        Copy +
        std::ops::BitXor<Output = T>
        >
    (x: T, y: T, z:T) -> T {
        x ^ y ^ z
    }

    pub fn shr<T:
        Copy + 
        std::ops::Shr<usize, Output = T>
        >
    (x: T, n: usize) -> T {
        x >> n
    }

    pub fn rot_r<T:
        Copy +
        std::ops::BitOr<Output = T> + 
        std::ops::Shr<usize, Output = T> +
        std::ops::Shl<usize, Output = T>
        >
    (x: T, n: usize) -> T {
        (x >> n) | (x << check_size::<T>() - n)
    }

    pub fn rot_l<T:
        Copy +
        std::ops::BitOr<Output = T> + 
        std::ops::Shr<usize, Output = T> +
        std::ops::Shl<usize, Output = T>
        >
    (x: T, n: usize) -> T {
        (x << n) | (x >> check_size::<T>() - n)
    }

    pub fn check_size<T>() -> usize {
        std::mem::size_of::<T>() * 8 // Convertir de bytes a bits
    }

}

pub mod functions { 

    use super::operations::{rot_r, shr};

    pub fn f<T: Copy + std::ops::BitXor<Output = T> + std::ops::BitAnd<Output = T> + std::ops::Not<Output = T>
    >(t: u8, x: T, y: T, z: T) -> Result<T, crate::err_handling::ShaError> {
        let ret = match t {
            0..=19 => super::operations::ch(x, y, z),
            20..=39 => super::operations::parity(x, y, z),
            40..=59 => super::operations::maj(x, y, z),
            60..=79 => super::operations::parity(x, y, z),
            _ => Err(crate::err_handling::ShaError::CustomError("Invalid value for t".to_string()))?,
        };
        Ok(ret)
    }
    
    pub fn csigma_0<T:
        'static +
        Copy +
        std::ops::BitOr<Output = T> + 
        std::ops::Shr<usize, Output = T> +
        std::ops::Shl<usize, Output = T> +
        std::ops::BitXor< Output = T>
        >
    (x: T) -> Result<T, crate::err_handling::ShaError> {
        let type_id = std::any::TypeId::of::<T>();
        match type_id {
            t if t == std::any::TypeId::of::<u32>() => Ok(rot_r(x,2) ^ rot_r(x,13) ^ rot_r(x,22)),
            t if t == std::any::TypeId::of::<u64>() => Ok(rot_r(x,28) ^ rot_r(x,34) ^ rot_r(x,39)),
            _ => Err(crate::err_handling::ShaError::CustomError("Invalid integer type".to_string()))
        }
    }

    pub fn csigma_1<T:
        'static +
        Copy +
        std::ops::BitOr<Output = T> + 
        std::ops::Shr<usize, Output = T> +
        std::ops::Shl<usize, Output = T> +
        std::ops::BitXor< Output = T>
        >
    (x: T) -> Result<T, crate::sha_lib::err_handling::ShaError> {
        let type_id = std::any::TypeId::of::<T>();
        match type_id {
            t if t == std::any::TypeId::of::<u32>() => Ok(rot_r(x,6) ^ rot_r(x,11) ^ rot_r(x,25)),
            t if t == std::any::TypeId::of::<u64>() => Ok(rot_r(x,14) ^ rot_r(x,18) ^ rot_r(x,41)),
            _ => Err(crate::err_handling::ShaError::CustomError("Invalid integer type".to_string()))
        }
    }

    pub fn sigma_0<T:
        'static +
        Copy +
        std::ops::BitOr<Output = T> + 
        std::ops::Shr<usize, Output = T> +
        std::ops::Shl<usize, Output = T> +
        std::ops::BitXor< Output = T>
        >
    (x: T) -> Result<T, crate::sha_lib::err_handling::ShaError> {
        let type_id = std::any::TypeId::of::<T>();
        match type_id {
            t if t == std::any::TypeId::of::<u32>() => Ok(rot_r(x,7) ^ rot_r(x,18) ^ shr(x,3)),
            t if t == std::any::TypeId::of::<u64>() => Ok(rot_r(x,1) ^ rot_r(x,8) ^ shr(x,7)),
            _ => Err(crate::err_handling::ShaError::CustomError("Invalid integer type".to_string()))
        }
    }

    pub fn sigma_1<T:
        'static +
        Copy +
        std::ops::BitOr<Output = T> + 
        std::ops::Shr<usize, Output = T> +
        std::ops::Shl<usize, Output = T> +
        std::ops::BitXor< Output = T>
        >
    (x: T) -> Result<T, crate::sha_lib::err_handling::ShaError> {
        let type_id = std::any::TypeId::of::<T>();
        match type_id {
            t if t == std::any::TypeId::of::<u32>() => Ok(rot_r(x,17) ^ rot_r(x,19) ^ shr(x,10)),
            t if t == std::any::TypeId::of::<u64>() => Ok(rot_r(x,19) ^ rot_r(x,61) ^ shr(x,6)),
            _ => Err(crate::err_handling::ShaError::CustomError("Invalid integer type".to_string()))
        }
    }
}

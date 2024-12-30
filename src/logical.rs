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
    >(t: u8, x: T, y: T, z: T) -> T {
        match t {
            0..=19 => super::operations::ch(x, y, z),
            20..=39 => super::operations::parity(x, y, z),
            40..=59 => super::operations::maj(x, y, z),
            60..=79 => super::operations::parity(x, y, z),
            _ => panic!("Invalid value for t"),
        }
    }
    
    pub fn csigma_0<T:
        'static +
        Copy +
        std::ops::BitOr<Output = T> + 
        std::ops::Shr<usize, Output = T> +
        std::ops::Shl<usize, Output = T> +
        std::ops::BitXor< Output = T>
        >
    (x: T) -> T {
        if std::any::TypeId::of::<T>() == std::any::TypeId::of::<u32>() {
            rot_r(x,2) ^ rot_r(x,13) ^ rot_r(x,22)
        } else if std::any::TypeId::of::<T>() == std::any::TypeId::of::<u64>() {
            rot_r(x,28) ^ rot_r(x,34) ^ rot_r(x,39)
        } else {
            panic!()
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
    (x: T) -> T {
        if std::any::TypeId::of::<T>() == std::any::TypeId::of::<u32>() {
            rot_r(x,6) ^ rot_r(x,11) ^ rot_r(x,25)
        } else if std::any::TypeId::of::<T>() == std::any::TypeId::of::<u64>() {
            rot_r(x,14) ^ rot_r(x,18) ^ rot_r(x,41)
        } else {
            panic!()
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
    (x: T) -> T {
        if std::any::TypeId::of::<T>() == std::any::TypeId::of::<u32>() {
            rot_r(x,7) ^ rot_r(x,18) ^ shr(x,3)
        } else if std::any::TypeId::of::<T>() == std::any::TypeId::of::<u64>() {
            rot_r(x,1) ^ rot_r(x,8) ^ shr(x,7)
        } else {
            panic!()
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
    (x: T) -> T {
        if std::any::TypeId::of::<T>() == std::any::TypeId::of::<u32>() {
            rot_r(x,17) ^ rot_r(x,19) ^ shr(x,10)
        } else if std::any::TypeId::of::<T>() == std::any::TypeId::of::<u64>() {
            rot_r(x,19) ^ rot_r(x,61) ^ shr(x,6)
        } else {
            panic!()
        }
    }
}

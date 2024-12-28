

pub fn ch<T: 
        Copy + 
        std::ops::BitAnd<Output = T> + 
        std::ops::BitOr<Output = T> + 
        std::ops::Not<Output = T>
        >
    (x: T, y: T, z: T) -> T {
    (x & y) ^ (!x & z)
}

pub fn maj<T:
        Copy + 
        std::ops::BitAnd<Output = T> + 
        std::ops::BitOr<Output = T>
        >
    (x: T, y: T, z: T) -> T {
    (x & y) ^ (x & z) ^ (y & z)
}

pub fn parity<T:
        Copy +
        std::ops::BitAnd<Output = T> + 
        std::ops::BitOr<Output = T> + 
        std::ops::Not<Output = T>
        >
    (x: T, y: T, z:T) -> T {
    x ^ y ^ z
}


extern crate num;

use crate::algorithm::blockcipher::{BlockCipher,BitwiseOperator};


use num::{PrimInt, NumCast, ToPrimitive};
use std::mem::size_of;
use std::cmp::{max};

/*  -------------------------------------
            RC5 Structure 
    -------------------------------------*/

pub struct RC5 <T:PrimInt> {
    w: T,              // WORD size in bits
    r: T,              // Number of Rounds
    b: T,              // Number of bytes in key
    t: T,              // Size of the table
    subkeys: Vec<T>,   // Expanded key table
    mask: T,           // 2^w - 1 
    p: T,              // Magic Number
    q: T,              // Magic Number
}

/*  -------------------------------------
            Implementations
    -------------------------------------*/

impl<T> RC5<T>  where T: PrimInt + NumCast {
    
    fn odd (x: T) -> T where T: PrimInt {
        if (x % T::from(2).unwrap())==T::one() {x} else {x + T::one()} 
    }

    pub fn new (wordsize:T, rounds:T, keybytes: T) -> Self  // Initialize the RC5 Control Block
    where T: PrimInt  {
        RC5 {
                w: wordsize,
                r: rounds,
                b: keybytes,
                t: T::from(2).unwrap()*(rounds + T::one()),
                subkeys: vec![T::zero(); (2 * (ToPrimitive::to_u8(&rounds).unwrap() + 1)) as usize],
                mask:  T::max_value() >> (size_of::<T>()*8 - ToPrimitive::to_usize(&wordsize).unwrap()),
                p: Self::odd(NumCast::from(0xB7E151628AED2A6B_u64 >> (64 - ToPrimitive::to_usize(&wordsize).unwrap())).unwrap()),
                q: Self::odd(NumCast::from(0x9E3779B97F4A7C15_u64 >> (64 - ToPrimitive::to_usize(&wordsize).unwrap())).unwrap()),
            }
        }
    }

    
/*  -------------------------------------
        Bitwise Operator Trait for RC5 
    -------------------------------------*/

impl<T: PrimInt> BitwiseOperator<T> for RC5<T> where T: PrimInt {
    
    // ---------------- Rotate Left ----------------

    fn rol (&self, w: T, n: T) -> T where T : PrimInt {
        let modn = n % self.w; // For non-standard w

        let v = w & self.mask;  

        if modn > T::zero()  {
            //((w << modn) & Self::mask) | ((w >> (lowbits+1 - modn)) & Self::mask)
            ((v.unsigned_shl(ToPrimitive::to_u32(&modn).unwrap())) & self.mask) | 
            ((v.unsigned_shr(ToPrimitive::to_u32(&(self.w - modn)).unwrap())) & self.mask)
        }
        else{
            v
        }
    }
    
    // ---------------- Rotate Right ----------------

    fn ror (&self,w: T, n: T) -> T{
        let modn = n % self.w; // For non-standard w

        let v = w & self.mask;

        if modn > T::zero()  {
            //((w >> modn) & Self::mask) | ((w << (lowbits+1 - modn)) & Self::mask)
            ((v.unsigned_shr(ToPrimitive::to_u32(&modn).unwrap())) & self.mask) | 
            ((v.unsigned_shl(ToPrimitive::to_u32(&(self.w - modn)).unwrap())) & self.mask)
        }
        else{
            v
        }
    }

    // ---------------- Modular Addition ----------------

    fn modadd (a:T, b:T) -> T where T: PrimInt + NumCast {
        let numbits: u8 = 8 * size_of::<T>() as u8;

        match numbits {
             8 => T::from(ToPrimitive::to_u8(&a).unwrap().wrapping_add(ToPrimitive::to_u8(&b).unwrap())).unwrap(),
            16 => T::from(ToPrimitive::to_u16(&a).unwrap().wrapping_add(ToPrimitive::to_u16(&b).unwrap())).unwrap(),
            32 => T::from(ToPrimitive::to_u32(&a).unwrap().wrapping_add(ToPrimitive::to_u32(&b).unwrap())).unwrap(),
            64 => T::from(ToPrimitive::to_u64(&a).unwrap().wrapping_add(ToPrimitive::to_u64(&b).unwrap())).unwrap(),
            _ => T::from(ToPrimitive::to_u128(&a).unwrap().wrapping_add(ToPrimitive::to_u128(&b).unwrap())).unwrap(),
        }
    }
    
    // ---------------- Modular Subtraction ----------------

    fn modsub (a:T, b:T) -> T {
        let numbits: u8 = 8 * size_of::<T>() as u8;

        match numbits {
             8 => T::from(ToPrimitive::to_u8(&a).unwrap().wrapping_sub(ToPrimitive::to_u8(&b).unwrap())).unwrap(),
            16 => T::from(ToPrimitive::to_u16(&a).unwrap().wrapping_sub(ToPrimitive::to_u16(&b).unwrap())).unwrap(),
            32 => T::from(ToPrimitive::to_u32(&a).unwrap().wrapping_sub(ToPrimitive::to_u32(&b).unwrap())).unwrap(),
            64 => T::from(ToPrimitive::to_u64(&a).unwrap().wrapping_sub(ToPrimitive::to_u64(&b).unwrap())).unwrap(),
            _ => T::from(ToPrimitive::to_u128(&a).unwrap().wrapping_sub(ToPrimitive::to_u128(&b).unwrap())).unwrap(),
        }
    }
}

/*  -------------------------------------
        BlockCipher Trait for RC5 
    -------------------------------------*/

impl<T> BlockCipher<T> for RC5<T> where T: PrimInt {
    
    // ---------------- Setup ----------------

    fn setup(&mut self, key: &[u8])  {
        let mut a : T = T::zero();
        let mut b : T = T::zero();
        
        // u = Number of bytes per Word
        let u = max(1, ToPrimitive::to_usize(&(self.w / T::from(8).unwrap())).unwrap()); 
        
        // Length of L
        let c: u8 = ((max(1, ToPrimitive::to_u8(&self.b).unwrap()) as f32) / (u as f32)).ceil() as u8;
        
        // st = t as u8
        let st= ToPrimitive::to_u8(&self.t).unwrap();
        
        // Alignment
        let mut l : Vec<T> = vec![T::zero();c as usize];
        let B = ToPrimitive::to_usize(&(self.b)).unwrap();
        for i in 0..B {
            l[(B-1-i)/u] = Self::modadd(Self::rol(&*self,l[(B-1-i)/u], T::from(8).unwrap())  ,T::from(key[B-1-i]).unwrap());
        }

        // Initialize Subkeys
        self.subkeys[0] = self.p;
        for i in 1..(st as usize) {
            self.subkeys[i as usize] = Self::modadd(self.subkeys[(i-1) as usize], self.q)  & self.mask;
        }

        // Mixing
        let mut i : u8 = 0;
        let mut j : u8 = 0;
        for _ in 0..3*max(st as usize,c as usize) {
            a = Self::rol(&*self, Self::modadd(self.subkeys[i as usize], Self::modadd(a,b)), T::from(3).unwrap());
            self.subkeys[i as usize] = a;
            
            b = Self::rol(&*self, Self::modadd(l[j as usize], Self::modadd(a,b)), Self::modadd( a,b));
            l[j as usize] = b;
            
            i = (i+1) % st;
            j = (j+1) % c;
        }
    }
    
    // ---------------- Encryption ----------------
    
    fn encrypt(&self, plaintext: &[T;2]) -> [T;2] {
        let mut a = Self::modadd(plaintext[0], self.subkeys[0]);
        let mut b = Self::modadd(plaintext[1], self.subkeys[1]);

        for i in 1..ToPrimitive::to_usize(&(self.r + T::one())).unwrap() {
            a = Self::modadd(Self::rol(self,a ^ b, b), self.subkeys[2*(i as usize)])  & self.mask;
            b = Self::modadd(Self::rol(self,b ^ a, a), self.subkeys[2*(i as usize) + 1])  & self.mask;
        }

        [a,b]
    }

    // ---------------- Decryption ----------------

    fn decrypt(&self, ciphertext: &[T;2]) -> [T;2] {
        let mut a = ciphertext[0];
        let mut b = ciphertext[1];
        let R = ToPrimitive::to_usize(&(self.r + T::one())).unwrap();
        for i in 1..R {
            b = Self::ror(self, Self::modsub(b, self.subkeys[2*(R-i) + 1])  & self.mask, a) ^ a;
            a = Self::ror(self, Self::modsub(a, self.subkeys[2*(R-i)])  & self.mask, b) ^ b;
        }

        [Self::modsub(a, self.subkeys[0]), Self::modsub(b, self.subkeys[1])]
    }
}

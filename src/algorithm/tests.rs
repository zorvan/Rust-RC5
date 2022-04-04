
/*  -------------------------------------
    Test
-------------------------------------*/
use super::rc5::RC5;
use super::blockcipher::BlockCipher;

use std::convert::TryInto;
extern crate hex;

fn conv<T, const N:
 usize>(v: Vec<T>) -> [T; N] {
    v.try_into()
        .unwrap_or_else(|v: Vec<T>| panic!("Expected a Vec of length {} but it was {}", N, v.len()))
}

// ---------- 8/12/4 ---------- 

#[test]
fn test_8_12_4() {
    let k = "00010203";
    let p = "0001";
    let c = "212A";
    let mut alg = RC5::new(8, 12, 4);

    let key = (conv::<u8,4>(hex::decode(k).expect("Decoding failed"))).to_vec();
    let plain = conv::<u8,2>(hex::decode(p).expect("Decoding failed"));
    
    alg.setup(&key);
    let  cipher = alg.encrypt(&plain);
    
    let (_,temp,_) = unsafe{cipher.align_to::<u8>()};
    let temp = hex::encode_upper(temp);

    assert_eq!(temp, c);
}

// ---------- 16/16/8 ---------- 

#[test]
fn test_16_16_8() {
    let k = "0001020304050607";
    let p = "00010203";
    let c = "23A8D72E";
    let mut alg = RC5::new(16, 16, 8);
    
    let key = (conv::<u8,8>(hex::decode(k).expect("Decoding failed"))).to_vec();
    
    let temp = hex::decode(p).expect("Decoding failed");
    let temp: Vec<u16> = temp.chunks_exact(2).into_iter().map(|a| u16::from_ne_bytes([a[0], a[1]])).collect();
    let plain = conv::<u16,2>(temp);
    
    alg.setup(&key);
    let cipher = alg.encrypt(&plain);

    let (_,temp,_) = unsafe{cipher.align_to::<u8>()};
    let temp = hex::encode_upper(temp);

    assert_eq!(temp, c);
}

// ---------- 32/20/16 ---------- 

#[test]
fn test_32_20_16() {            
    let k = "000102030405060708090A0B0C0D0E0F";
    let p = "0001020304050607";
    let c = "2A0EDC0E9431FF73";
    let mut alg = RC5::new(32, 20, 16);
    
    let key = (conv::<u8,16>(hex::decode(k).expect("Decoding failed"))).to_vec();
    
    let temp = hex::decode(p).expect("Decoding failed");
    let temp: Vec<u32> = temp.chunks_exact(4).into_iter().map(|a| u32::from_ne_bytes([a[0], a[1], a[2], a[3]])).collect();
    let plain = conv::<u32,2>(temp);
    
    alg.setup(&key);
    let cipher = alg.encrypt(&plain);

    let (_,temp,_) = unsafe{cipher.align_to::<u8>()};
    let temp = hex::encode_upper(temp);

    assert_eq!(temp, c);
}

// ---------- 64/24/24 ---------- 

#[test]
fn test_64_24_24() {            
    let k = "000102030405060708090A0B0C0D0E0F1011121314151617";
    let p = "000102030405060708090A0B0C0D0E0F";
    let c = "A46772820EDBCE0235ABEA32AE7178DA";
    let mut alg = RC5::new(64, 24, 24);
    
    let key = (conv::<u8, 24>(hex::decode(k).expect("Decoding failed"))).to_vec();
    
    let temp = hex::decode(p).expect("Decoding failed");
    let temp: Vec<u64> = temp.chunks_exact(8).into_iter().map(|a| u64::from_ne_bytes([a[0], a[1], a[2], a[3],a[4], a[5], a[6], a[7]])).collect();
    let plain = conv::<u64,2>(temp);
    
    alg.setup(&key);
    let cipher = alg.encrypt(&plain);

    let (_,temp,_) = unsafe{cipher.align_to::<u8>()};
    let temp = hex::encode_upper(temp);

    assert_eq!(temp, c);
}

// ---------- non-Standard ---------- 

#[test]
fn test_24_4_0() {            
    let k = "";
    let p = "000102030405";
    let c = "9F8F61780F13";
    let mut alg = RC5::new(24, 4, 0);
    
    let key = hex::decode(k).expect("Decoding failed");
    alg.setup(&key);
    
    let p1 = format!("{:0<8}", &p[0..6]);
    let p2 = format!("{:0<8}", &p[6..12]);
    let temp1: Vec<u8> = hex::decode(&p1).expect("Decoding failed");
    let temp2: Vec<u8> = hex::decode(&p2).expect("Decoding failed");
    let temp1: Vec<u32>= temp1.chunks_exact(4).into_iter().map(|a| u32::from_ne_bytes([a[0], a[1], a[2], a[3]])).collect();
    let temp2: Vec<u32>= temp2.chunks_exact(4).into_iter().map(|a| u32::from_ne_bytes([a[0], a[1], a[2], a[3]])).collect();
    
    let plain: [u32;2] = [temp1[0],temp2[0]];
    
    let cipher = alg.encrypt(&plain);
    
    //let (_,temp,_) = unsafe{cipher.align_to::<u8>()};
    let mut temp = hex::encode_upper(cipher[0].to_le_bytes());
    let mut temp1 = hex::encode_upper(cipher[1].to_le_bytes());
    temp =  String::from(&temp [0..6]);
    temp1 = String::from(&temp1[0..6]);
    
    temp.push_str(&temp1);

    assert_eq!(temp, c);
}

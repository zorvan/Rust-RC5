mod algorithm;
use algorithm::rc5::RC5;
use algorithm::blockcipher::BlockCipher;

/*  -------------------------------------
                main
    -------------------------------------*/

fn main() {

    let mut alg = RC5::new(32, 12, 16);
    let key = vec![0u8;16];
    let plain = [0u32;2];

    alg.setup(&key);

    let  cipher = alg.encrypt(&plain);
    println!("Key = {:02X?}\nPlain Text = {:02X?}\nCipher Text = {:02X?}\n",key,to_bytes(&plain),to_bytes(&cipher));
}

/*  -------------------------------------
                Auxiliary Function
    -------------------------------------*/

use byteorder::{WriteBytesExt, LittleEndian};

fn to_bytes(input: &[u32]) -> Vec<u8> {
    /*let mut bytes = Vec::with_capacity(4 * input.len());
    
    for value in input {
        bytes.extend(&value.to_be_bytes());
    }

    bytes
    */
    let mut vec8: Vec<u8> = vec![];

    for elem in input {
        vec8.write_u32::<LittleEndian>(*elem).unwrap();
    }

    vec8
}
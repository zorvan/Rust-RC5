
/*  -------------------------------------
            RC5 Structure 
-------------------------------------*/
    
pub trait BlockCipher <T> {
    fn setup(&mut self, key: &Vec<u8>);
    fn encrypt(&self, plaintext: &[T;2]) -> [T;2];
    fn decrypt(&self, ciphertext: &[T;2]) -> [T;2];
}


pub trait BitwiseOperator<T> {
    fn rol (&self, w: T, n: T) -> T;
    fn ror (&self, w: T, n: T) -> T;
    fn modadd (a:T, b:T) -> T;
    fn modsub (a:T, b:T) -> T;
}


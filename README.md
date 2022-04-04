# RC5

Coding Challenge: RC5 Cryptographic Algorithm in Rust

## Design Considerations

- Using generic types for allowable WORD sizes (u8,u16,u32,u64,u128)
- Supporting non-standard modes of RC5 algorithm (non power of 2 key length, arbitrary W > 0)
- Design a structure for adding more algorithms in the future
- Avoiding unsafe codes
- Applying both OOP and Functional styles
- Efficient memory usage for embedded system applications
- Minimum usage of external crates

## Usage

For testing : 

    $ cargo test
 
For running :     
	
	$ cargo run

### To Do
- Embedding Pre and Post processing of plain/cipher texts in the algorithm (i.e test 24_4_0)


## License
Copyright © 2021 Amin Razavi

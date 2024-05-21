//! In Module 1, we discussed Block ciphers like AES. Block ciphers have a fixed length input.
//! Real wold data that we wish to encrypt _may_ be exactly the right length, but is probably not.
//! When your data is too short, you can simply pad it up to the correct length.
//! When your data is too long, you have some options.
//!
//! In this exercise, we will explore a few of the common ways that large pieces of data can be
//! broken up and combined in order to encrypt it with a fixed-length block cipher.
//!
//! WARNING: ECB MODE IS NOT SECURE.
//! Seriously, ECB is NOT secure. Don't use it irl. We are implementing it here to understand _why_
//! it is not secure and make the point that the most straight-forward approach isn't always the
//! best, and can sometimes be trivially broken.
use hex::encode;
use rand::Rng;
use sha2::{digest::block_buffer::Error, Digest, Sha256};

use aes::{
    cipher::{generic_array::GenericArray, BlockCipher, BlockDecrypt, BlockEncrypt, KeyInit},
    Aes128,
};

///We're using AES 128 which has 16-byte (128 bit) blocks.
const BLOCK_SIZE: usize = 16;

fn main() {
    // Define the size of the vector
    let size: usize = 300; // Arbitrary size

    // Create a vector of u8 with incrementing integers using % 255 to avoid wrapping
    let vec: Vec<u8> = (0..size).map(|i| (i % 255) as u8).collect();
    let result = un_pad(&un_group(&group(&pad(&vec))));

    // println!(
    //     "{}",
    //     pad(&vec)
    //         .iter()
    //         .map(|x| x.to_string())
    //         .collect::<Vec<String>>()
    //         .join(", ")
    // );

    // println!(
    //     "{}",
    //     &group(&pad(&vec))[0]
    //         .iter()
    //         .map(|x| x.to_string())
    //         .collect::<Vec<String>>()
    //         .join(", ")
    // );

    // println!(
    //     "{}",
    //     &group(&pad(&vec))[1]
    //         .iter()
    //         .map(|x| x.to_string())
    //         .collect::<Vec<String>>()
    //         .join(", ")
    // );

    // println!(
    //     "{}",
    //     &un_group(&group(&pad(&vec)))
    //         .iter()
    //         .map(|x| x.to_string())
    //         .collect::<Vec<String>>()
    //         .join(", ")
    // );

    // println!(
    //     "{}",
    //     un_pad(&un_group(&group(&pad(&vec))))
    //         .iter()
    //         .map(|x| x.to_string())
    //         .collect::<Vec<String>>()
    //         .join(", ")
    // );

    println!("{}", hash_vec(&result) == hash_vec(&result));
    println!("{}", hash_vec(&result) == hash_vec(&vec));

    let plain_text: Vec<u8> = "Hello pba".chars().map(|c| c as u8).collect();
    let key: [u8; 16] = [
        1u8, 2u8, 3u8, 4u8, 1u8, 2u8, 3u8, 4u8, 1u8, 2u8, 3u8, 4u8, 1u8, 2u8, 3u8, 4u8,
    ];
    let encrypted = ecb_encrypt(plain_text.clone(), key);

    println!(
        "the result of encrypting {:?} => {:?}",
        plain_text.clone(),
        encrypted
    );

    let decrypted = ecb_decrypt(encrypted, key);
    println!("decrypted: {:?}", decrypted);

    // CTR algo

    let nonce: [u8; 8] = rand::thread_rng().gen::<[u8; 8]>();
}

fn hash_vec(data: &Vec<u8>) -> String {
    // Create a Sha256 hasher instance
    let mut hasher = Sha256::new();

    // Feed the data into the hasher
    hasher.update(data);

    // Retrieve the resulting hash
    let result = hasher.finalize();

    // Convert the result to a hexadecimal string
    encode(result)
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_encrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.encrypt_block(&mut block);

    block.into()
}

/// Simple AES encryption
/// Helper function to make the core AES block cipher easier to understand.
fn aes_decrypt(data: [u8; BLOCK_SIZE], key: &[u8; BLOCK_SIZE]) -> [u8; BLOCK_SIZE] {
    // Convert the inputs to the necessary data type
    let mut block = GenericArray::from(data);
    let key = GenericArray::from(*key);

    let cipher = Aes128::new(&key);

    cipher.decrypt_block(&mut block);

    block.into()
}

/// Before we can begin encrypting our raw data, we need it to be a multiple of the
/// block length which is 16 bytes (128 bits) in AES128.
///
/// The padding algorithm here is actually not trivial. The trouble is that if we just
/// naively throw a bunch of zeros on the end, there is no way to know, later, whether
/// those zeros are padding, or part of the message, or some of each.
///
/// The scheme works like this. If the data is not a multiple of the block length,  we
/// compute how many pad bytes we need, and then write that number into the last several bytes.
/// Later we look at the last byte, and remove that number of bytes.
///
/// But if the data _is_ a multiple of the block length, then we have a problem. We don't want
/// to later look at the last byte and remove part of the data. Instead, in this case, we add
/// another entire block containing the block length in each byte. In our case,
/// [16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16, 16]
fn pad(data: &Vec<u8>) -> Vec<u8> {
    // When twe have a multiple the second term is 0
    let number_pad_bytes = BLOCK_SIZE - data.len() % BLOCK_SIZE;

    let mut res = data.clone();

    for _ in 0..number_pad_bytes {
        res.push(number_pad_bytes as u8);
    }

    res
}

/// Groups the data into BLOCK_SIZE blocks. Assumes the data is already
/// a multiple of the block size. If this is not the case, call `pad` first.
fn group(data: &Vec<u8>) -> Vec<[u8; BLOCK_SIZE]> {
    let mut blocks = Vec::new();
    let mut i = 0;
    while i < data.len() {
        let mut block: [u8; BLOCK_SIZE] = Default::default();
        block.copy_from_slice(&data[i..i + BLOCK_SIZE]);
        blocks.push(block);

        i += BLOCK_SIZE;
    }

    blocks
}

/// Does the opposite of the group function
fn un_group(blocks: &Vec<[u8; BLOCK_SIZE]>) -> Vec<u8> {
    let mut data = Vec::new();
    for block in blocks {
        data.extend_from_slice(block);
    }
    data
}

/// Does the opposite of the pad function.
fn un_pad(data: &Vec<u8>) -> Vec<u8> {
    let number_pad_bytes: usize = data.last().unwrap_or(&0).clone().into();

    let mut res = data.clone();

    res.truncate(data.len() - number_pad_bytes);
    res
}

/// The first mode we will implement is the Electronic Code Book, or ECB mode.
/// Warning: THIS MODE IS NOT SECURE!!!!
///
/// This is probably the first thing you think of when considering how to encrypt
/// large data. In this mode we simply encrypt each block of data under the same key.
/// One good thing about this mode is that it is parallelizable. But to see why it is
/// insecure look at: https://www.ubiqsecurity.com/wp-content/uploads/2022/02/ECB2.png
fn ecb_encrypt(plain_text: Vec<u8>, key: [u8; 16]) -> Vec<u8> {
    group(&pad(&plain_text))
        .into_iter()
        .fold(Vec::new(), |mut cipher_text, block| {
            cipher_text.extend_from_slice(&aes_encrypt(block, &key));
            cipher_text
        })
}

/// Opposite of ecb_encrypt.
fn ecb_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    group(&cipher_text)
        .into_iter()
        .fold(Vec::new(), |mut plain_text, block| {
            plain_text.extend_from_slice(&un_pad(&aes_decrypt(block, &key).to_vec()));
            plain_text
        })
}

/// The next mode, which you can implement on your own is cipherblock chaining.
/// This mode actually is secure, and it often used in real world applications.
///
/// In this mode, the ciphertext from the first block is XORed with the
/// plaintext of the next block before it is encrypted.
///
/// For more information, and a very clear diagram,
/// see https://de.wikipedia.org/wiki/Cipher_Block_Chaining_Mode
///
/// You will need to generate a random initialization vector (IV) to encrypt the
/// very first block because it doesn't have a previous block. Typically this IV
/// is inserted as the first block of ciphertext.
fn cbc_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random initialization vector for the first block.

    todo!()
}

fn cbc_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    todo!()
}

/// Another mode which you can implement on your own is counter mode.
/// This mode is secure as well, and is used in real world applications.
/// It allows parallelized encryption and decryption, as well as random read access when decrypting.
///
/// In this mode, there is an index for each block being encrypted (the "counter"), as well as a random nonce.
/// For a 128-bit cipher, the nonce is 64 bits long.
///
/// For the ith block, the 128-bit value V of `nonce | counter` is constructed, where | denotes
/// concatenation. Then, V is encrypted with the key using ECB mode. Finally, the encrypted V is
/// XOR'd with the plaintext to produce the ciphertext.
///
/// A very clear diagram is present here:
/// https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Counter_(CTR)
///
/// Once again, you will need to generate a random nonce which is 64 bits long. This should be
/// inserted as the first block of the ciphertext.
///

fn xor(b1: String, b2: String) -> Result<String, &'static str> {
    if b1.len() != b2.len() {
        return Err("cannot xor different lengths");
    }
    let length = b1.len();
    let mut result = String::new();

    for i in 0..length {
        let c1 = b1.chars().nth(i).unwrap();
        let c2 = b2.chars().nth(i).unwrap();

        if c1 == c2 {
            result.push('0');
        } else {
            result.push('1');
        }
    }

    for _i in 0..length {
        result.push('0');
    }

    Ok(result)
}

fn getV(counter: u64, nonce: [u8; 8]) -> [u8; BLOCK_SIZE] {
    let mut counter_transfo: [u8; 8] = [0; 8];
    let mut counter_copy = counter;
    for i in 0..=7 {
        let last_digit_in_base128 = counter_copy % 128;
        counter_transfo[7-i] = last_digit_in_base128 as u8;
        counter_copy -= last_digit_in_base128;
        counter_copy /= 128;
    }

    let mut result: [u8; 16] = [0; 16];
    result[..8].copy_from_slice(&nonce);
    result[8..].copy_from_slice(&counter_transfo);
    result
}

fn ctr_encrypt(plain_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    // Remember to generate a random nonce
    group(&pad(&plain_text))
        .into_iter()
        .fold(Vec::new(), |mut cipher_text, block| {
            cipher_text.extend_from_slice(&aes_encrypt(block, &key));
            cipher_text
        })
}

fn ctr_decrypt(cipher_text: Vec<u8>, key: [u8; BLOCK_SIZE]) -> Vec<u8> {
    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_group() {
        // Test case 1: Data is a multiple of BLOCK_SIZE
        let data = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
            24, 25, 26, 27, 28, 29, 30, 31,
        ];
        let expected_blocks = vec![
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
            ],
        ];
        assert_eq!(group(&data), expected_blocks);
    }

    #[test]
    fn test_group_with_padding() {
        // Test case: Data length is not a multiple of BLOCK_SIZE, pad required
        let data: Vec<u8> = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, // 17 bytes
        ];
        let padded_data: Vec<u8> = pad(&data);
        let expected_padded_data: Vec<[u8; 16]> = vec![
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [
                16, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
            ],
        ];
        assert_eq!(group(&padded_data), expected_padded_data);
    }

    #[test]
    fn test_un_group() {
        // Test case: Data is ungrouped correctly
        let blocks = vec![
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
            [
                16, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15, 15,
            ],
        ];
        let expected_data = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 15, 15, 15, 15, 15, 15, 15,
            15, 15, 15, 15, 15, 15, 15, 15,
        ];

        assert_eq!(un_group(&blocks), expected_data);
    }

    #[test]
    fn test_un_pad() {
        // Test case: Data is unpadded correctly
        let padded_data: Vec<u8> = vec![
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 15, 15, 15, 15, 15, 15, 15,
            15, 15, 15, 15, 15, 15, 15, 15,
        ];
        let expected_data: Vec<u8> = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];

        assert_eq!(un_pad(&padded_data), expected_data);
    }
}

use rand::rngs::OsRng;
use rand::Rng;
use std::collections::HashMap;

static ASCII_LOWER: [char; 26] = [
    'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's',
    't', 'u', 'v', 'w', 'x', 'y', 'z',
];

fn num_to_char() -> HashMap<i32, &'static char> {
    let num_to_char: HashMap<i32, &char> = ASCII_LOWER
        .iter()
        .enumerate()
        .map(|(i, x)| (i as i32, x))
        .collect();

    num_to_char
}

fn char_to_num() -> HashMap<&'static char, i32> {
    let char_to_num: HashMap<&char, i32> = ASCII_LOWER
        .iter()
        .enumerate()
        .map(|(i, x)| (x, i as i32))
        .collect();

    char_to_num
}

fn extend_key(old_key: &str, required_length: usize) -> String {
    let mut new_key = old_key.to_string();
    let mut char_selector = 0;
    while new_key.len() < required_length {
        new_key.push(old_key.chars().nth(char_selector).unwrap());
        char_selector += 1;
        if char_selector >= old_key.len() {
            char_selector = 0;
        }
    }
    new_key
}

pub fn encrypt(plaintext: &str, key: &str) -> String {
    let chars_to_nums = char_to_num();
    let nums_to_chars = num_to_char();
    let mut key_internal = key.to_string();

    if key.len() < plaintext.len() {
        println!("Key length not sufficient, repeating key until length matches");
        key_internal = extend_key(key, plaintext.len());
    }

    let mut ciphertext = String::new();
    for (plaintext_c, key_c) in plaintext.chars().zip(key_internal.chars()) {
        let new_index = (chars_to_nums[&plaintext_c] + chars_to_nums[&key_c]) % 26;
        let new_char = nums_to_chars[&new_index];
        ciphertext.push(*new_char);
    }
    ciphertext
}

pub fn decrypt(ciphertext: &str, key: &str) -> String {
    let chars_to_nums = char_to_num();
    let nums_to_chars = num_to_char();
    let mut key_internal = key.to_string();

    if key.len() < ciphertext.len() {
        println!("Key length not sufficient, repeating key until length matches");
        key_internal = extend_key(key, ciphertext.len());
    }

    let mut plaintext = String::new();
    for (plaintext_c, key_c) in ciphertext.chars().zip(key_internal.chars()) {
        let new_index = (chars_to_nums[&plaintext_c] - chars_to_nums[&key_c]).rem_euclid(26);
        let new_char = nums_to_chars[&new_index];
        plaintext.push(*new_char);
    }
    plaintext
}

/// Generates a random key with length specified by the user.
pub fn random_key(length: usize) -> String {
    let nums_to_chars = num_to_char();
    let mut key = String::new();
    for _ in 0..length {
        key.push(*nums_to_chars[&OsRng.gen_range(0..25)]);
    }

    key
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_num_to_chars() {
        let map = num_to_char();
        assert_eq!(map[&0], &ASCII_LOWER[0]);
        assert_eq!(map[&22], &ASCII_LOWER[22]);
    }

    #[test]
    fn test_char_to_nums() {
        let map = char_to_num();
        assert_eq!(map[&ASCII_LOWER[7]], 7);
        assert_eq!(map[&ASCII_LOWER[15]], 15);
    }

    #[test]
    fn test_encrypt() {
        let plaintext = "abc";
        let key = "bcz";
        assert_eq!(encrypt(plaintext, key), "bdb");
    }

    #[test]
    fn test_encrypt_decrypt() {
        let plaintext = "asdfsdgsdfsda";
        let key = "ayrj";
        assert_eq!(decrypt(&encrypt(plaintext, key), key), plaintext);
    }
}

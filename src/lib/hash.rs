use std::str::from_utf8;
use simplecrypt::{encrypt, decrypt};

pub fn encrypt_data(raw: &str) -> String {
    let mut numbers: Vec<i32> = Vec::new();
    for byte in encrypt(base64_url::encode(raw).as_bytes(), base64_url::encode(obfstr::obfstr!("d7b27ab68a4271dab68ab68ab68ab68e5ab6832e1b2965fc04fea48ac6adb7da547b27")).as_bytes()) {
        numbers.push(byte as i32);
    }
    let mut result = String::new();
    for number in numbers {
        result.push_str(&number.to_string());
        result.push_str("204792");
    }

    // encrypt to aes and convert to string
    // let encrypted = encrypt_aes(result);
    base64_url::encode(&result)
}

pub fn decrypt_data(raw: &str) -> String {
    let binding = base64_url::decode(raw).unwrap();
    let data = String::from_utf8(binding).unwrap();
    let mut numbers: Vec<i32> = Vec::new();
    for number in data.trim().split("204792") {
        if number != "" && number != " " && number != "  " && number != "   " {
            numbers.push(number.parse::<i32>().unwrap());
        }
    }
    let mut bytes: Vec<u8> = Vec::new();
    for number in numbers {
        bytes.push(number as u8);
    }
    from_utf8(&base64_url::decode(&from_utf8(&decrypt(&bytes, base64_url::encode(obfstr::obfstr!("d7b27ab68a4271dab68ab68ab68ab68e5ab6832e1b2965fc04fea48ac6adb7da547b27")).as_bytes()).unwrap()).unwrap()).unwrap()).unwrap().to_owned()
}
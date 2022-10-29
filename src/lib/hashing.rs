use crate::KEY;

static mut NUMBERS: Vec<i32> = Vec::new();
static mut LETTERS: Vec<char> = Vec::new();

fn concat(one: String, two: String) -> String {
    let mut result = String::new();
    result.push_str(&one);
    result.push_str(&two);
    return result;
}

pub fn encrypt(raw: &str) -> String {
    let key = KEY;
    let mut n: String = "".to_string();
    unsafe {LETTERS = vec!['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '!', '"', '#', '$', '%', '&', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~', ' ', '\t', '\n', '\r', '\x0b', '\x0c', 'à', '\'']}
    for i in 1..1000 {
        unsafe{NUMBERS.push(i);}
    }
    for (i, c) in raw.chars().enumerate() {
        n = concat(n.to_string(), "294".to_string());
        unsafe{n = concat(n.to_string(), NUMBERS[i+27+LETTERS.iter().position(|&r| r == c).unwrap()].to_string());}
    }
    let mut enc_coef:String = "".to_string();

    for (i, c) in key.chars().enumerate() {
        unsafe{enc_coef = concat(enc_coef.to_string(), NUMBERS[i+27+LETTERS.iter().position(|&r| r == c).unwrap()].to_string())}
    }


    let mut result_str: String = concat(n.to_string(), enc_coef.to_string());
    result_str = concat(result_str.to_string(), "2191879".to_string());
    result_str = concat(result_str.to_string(), "0795".to_string());

    return result_str;
}


pub fn decrypt(encrypted: &str) -> String {
    let key = KEY;
    unsafe {LETTERS = vec!['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '!', '"', '#', '$', '%', '&', '(', ')', '*', '+', ',', '-', '.', '/', ':', ';', '<', '=', '>', '?', '@', '[', '\\', ']', '^', '_', '`', '{', '|', '}', '~', ' ', '\t', '\n', '\r', '\x0b', '\x0c', 'à', '\'']}
    for i in 1..1000 {
        unsafe{NUMBERS.push(i);}
    }
    let mut enc_coef:String = "".to_string();
    let mut result: String = "".to_string();
    for (i, c) in key.chars().enumerate() {
        unsafe{enc_coef = concat(enc_coef.to_string(), NUMBERS[i+27+LETTERS.iter().position(|&r| r == c).unwrap()].to_string())}
    }

    result = encrypted.replace(&enc_coef, "");
    result = result.replace("2191879", "");
    result = result.replace("0795", "");

    let split = result.split("294");
    let mut split_vec: Vec<&str> = Vec::new();
    for i in split {
        split_vec.push(i);
    }
    split_vec.remove(0);
    let mut _final_s = "".to_string();
    let mut j = 0;
    // revert what was done in the encrypt function with the index of NUMBERS and LETTERS
    for i in split_vec {
        if i != "" {
        let k = i.parse::<u128>().unwrap();
        unsafe{_final_s = concat(_final_s.to_string(), LETTERS[NUMBERS.iter().position(|&r| r == k as i32).unwrap()-27-j].to_string())}
        j += 1;
    }
    }

    return _final_s;
}
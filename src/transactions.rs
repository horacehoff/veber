use std::{fs::File, io::Write};
use crate::{compute_personal_hash, ResponseStruct, Users, User, IS_LIVE, encrypt, KEY, read_users};




pub fn _check_transaction_hash(username: &str, password: &str, uid: u128) -> bool {
    let hash = compute_personal_hash(username, password, uid);
    let users = read_users();
    for user in users.users_data {
        if user.username == username && user.password == password && user.uid == uid && user.personal_hash == hash {
            return true;
        }
    }
    return false;
}

pub fn _get_user_balance(username: &str, password: &str, uid: u128) -> f64 {
    let users = read_users();
    for user in users.users_data {
        if user.username == username && user.password == password && user.uid == uid {
            return user.balance;
        }
    }
    return 0.0;
}

pub fn _check_transaction(username_sender: &str, password_sender: &str, uid_sender: u128, amount: f64) -> bool {
    if _check_transaction_hash(username_sender, password_sender, uid_sender) {
        // process transaction
        if (_get_user_balance(username_sender, password_sender, uid_sender) - amount) >= 0.0 {
            return true;
        } else {
            return false;
        }
    } else {
        return false;
    }
}

pub fn _process_transaction(username_sender: &str, password_sender: &str, uid_sender: u128, username_t: &str, amount: f64) -> ResponseStruct {
    let users = read_users();
    let mut new_users = Users {
        users_data: Vec::new()
    };
    if _check_transaction(username_sender, password_sender, uid_sender, amount) && unsafe{IS_LIVE} && username_sender != "" && password_sender != "" && uid_sender != 0 && username_t != "" && amount != 0.0 && _check_transaction_hash(username_sender, password_sender, uid_sender) {
        for user in users.users_data {
            if user.username == username_sender && user.password == password_sender && user.uid == uid_sender {
                let new_user = User {
                    username: user.username,
                    password: user.password,
                    uid: user.uid,
                    balance: user.balance - amount,
                    personal_hash: user.personal_hash
                };
                new_users.users_data.push(new_user);
            } else if user.username == username_t {
                let new_user = User {
                    username: user.username,
                    password: user.password,
                    uid: user.uid,
                    balance: user.balance + amount,
                    personal_hash: user.personal_hash
                };
                new_users.users_data.push(new_user);
            }
        }
        let mut to_search:Vec<String> = Vec::new();
        to_search.push(encrypt(KEY, username_sender));
        to_search.push(encrypt(KEY, username_t));
        // delete the file of the first user
        std::fs::remove_file(format!("data/{}.db", to_search[0])).unwrap();
        // delete the file of the second user
        std::fs::remove_file(format!("data/{}.db", to_search[1])).unwrap();
        // write the new data of the first user
        let mut file = File::create(format!("data/{}.db", to_search[0])).unwrap();
        let first_user_data = encrypt(KEY, serde_json::to_string(&new_users.users_data[0]).unwrap().to_string().as_str());
        file.write_all(first_user_data.as_bytes()).unwrap();
        // write the new data of the second user
        let mut file = File::create(format!("data/{}.db", to_search[1])).unwrap();
        let second_user_data = encrypt(KEY, serde_json::to_string(&new_users.users_data[1]).unwrap().to_string().as_str());
        file.write_all(second_user_data.as_bytes()).unwrap();

        
        return ResponseStruct {
            status: String::from("[SUCCESS]"),
            message: String::from("Transaction successful")
        }
    } else {
        return ResponseStruct {
            status: String::from("[ERROR]"),
            message: String::from("Transaction failed")
        }
    }
}
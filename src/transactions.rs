use std::{fs::File, io::Write};
use crate::lib::hash::encrypt_data;
use crate::{compute_personal_hash, Users, User, TRANSACTION_FEE, OWNER_ACCOUNT_USERNAME, OWNER_ACCOUNT_PASSWORD, OWNER_ACCOUNT_UID};
use crate::read_users;
use crate::IS_LIVE;
use crate::ResponseStruct;




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
        if (_get_user_balance(username_sender, password_sender, uid_sender) - amount - TRANSACTION_FEE) >= 0.0 {
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
    let mut is_checked = false;
    // additional security checks
    for user in read_users().users_data {
        if user.username == username_sender && user.password == password_sender && user.uid == uid_sender && compute_personal_hash(username_sender, password_sender, uid_sender) == user.personal_hash {
            is_checked = true;
        }
    }
    if is_checked && _check_transaction(username_sender, password_sender, uid_sender, amount) && unsafe{IS_LIVE} && username_sender != "" && password_sender != "" && uid_sender != 0 && username_t != "" && amount != 0.0 && _check_transaction_hash(username_sender, password_sender, uid_sender) {
        for user in users.users_data {
            if user.username == username_sender && user.password == password_sender && user.uid == uid_sender && user.personal_hash == compute_personal_hash(username_sender, password_sender, uid_sender) {
                let new_user = User {
                    username: user.username,
                    password: user.password,
                    uid: user.uid,
                    balance: user.balance - amount - TRANSACTION_FEE,
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
        new_users.users_data.push(User {
            username: OWNER_ACCOUNT_USERNAME.to_string(),
            password: OWNER_ACCOUNT_PASSWORD.to_string(),
            uid: OWNER_ACCOUNT_UID,
            balance: _get_user_balance(OWNER_ACCOUNT_USERNAME, OWNER_ACCOUNT_PASSWORD, OWNER_ACCOUNT_UID) + TRANSACTION_FEE,
            personal_hash: compute_personal_hash(OWNER_ACCOUNT_USERNAME, OWNER_ACCOUNT_PASSWORD, OWNER_ACCOUNT_UID)
        });
        // write the new data of the first user
        let mut file = File::create(format!("data/{}.db", base64_url::encode(username_sender))).unwrap();
        let first_user_data = encrypt_data(serde_json::to_string(&new_users.users_data[0]).unwrap().to_string().as_str());
        file.write_all(first_user_data.as_bytes()).unwrap();
        // write the new data of the second user
        let mut file = File::create(format!("data/{}.db", base64_url::encode(username_t))).unwrap();
        let second_user_data = encrypt_data(serde_json::to_string(&new_users.users_data[1]).unwrap().to_string().as_str());
        file.write_all(second_user_data.as_bytes()).unwrap();
        // write the new data of the admin with the new transaction fee
        if username_sender != OWNER_ACCOUNT_USERNAME && password_sender != OWNER_ACCOUNT_PASSWORD && uid_sender != OWNER_ACCOUNT_UID {
            let mut file = File::create(format!("data/{}.db", base64_url::encode(OWNER_ACCOUNT_USERNAME))).unwrap();
            let admin_user_data = encrypt_data(serde_json::to_string(&new_users.users_data[2]).unwrap().to_string().as_str());
            file.write_all(admin_user_data.as_bytes()).unwrap();
        }
        return ResponseStruct {
            status: String::from("SUCCESS"),
            message: String::from("Transaction successful")
        }
    } else {
        return ResponseStruct {
            status: String::from("ERROR"),
            message: String::from("Transaction failed")
        }
    }
}


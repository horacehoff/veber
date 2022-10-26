use std::{fs::{File}, io::{Read, Write, BufReader, BufRead}, net::TcpStream};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha512_256, Sha224, Sha512_224};
use threadpool::ThreadPool;
use transactions::_process_transaction;
use std::net::TcpListener;
mod transactions;

static mut IS_LIVE: bool = true;
static KEY: &str = "d7b27ab68a4271dab68ab68ab68ab68e5ab6832e1b2965fc04fea48ac6adb7da547b27";

#[derive(Serialize, Deserialize, Debug)]
pub struct User {
    username: String,
    password: String,
    uid: u128,
    personal_hash: String,
    balance: f64
}

#[derive(Serialize, Deserialize, Debug)]
pub struct Users {
    users_data: Vec<User>
}

#[derive(Serialize, Deserialize)]
pub struct ResponseStruct {
    status: String,
    message: String
}

fn compute_personal_hash(username: &str, password: &str, uid: u128) -> String {
    let mut layer_one = Sha512_256::new();
    let mut layer_two = Sha224::new();
    let mut layer_three = Sha512_224::new();

    // LAYER ONE - SHA512_256
    layer_one.update(username.as_bytes());

    // LAYER TWO - SHA224
    layer_two.update(password.as_bytes());

    // LAYER THREE  SHA512_224
    layer_three.update(uid.to_string().as_bytes());

    let result_one = layer_one.finalize();
    let result_two = layer_two.finalize();
    let result_three = layer_three.finalize();
    // blend the results
    let mut final_result = result_one.to_vec();
    final_result.extend(result_two.to_vec());
    final_result.extend(result_three.to_vec());
    let hash_str = final_result.iter().map(|x| format!("{:02x}", x)).collect::<String>();
    return hash_str;
}

fn encrypt_slayer(key: &str, data: &str) -> String {
    let mc = new_magic_crypt!(key, 256);
    let encrypted = mc.encrypt_str_to_base64(data);
    return encrypted;
}

fn decrypt_slayer(key: &str, data: &str) -> String {
    let mc = new_magic_crypt!(key, 256);
    let decrypted = mc.decrypt_base64_to_string(data);
    match decrypted {
        Ok(decrypted) => return decrypted,
        Err(_) => return String::from(""),
    }
}

fn encrypt(key: &str, data: &str) -> String {
    let mcrypt = new_magic_crypt!(key, 256);
    let encrypted = mcrypt.encrypt_str_to_base64(data);
    return encrypt_slayer(KEY, encrypted.as_str());
}

fn decrypt(key: &str, data: &str) -> String {
    let mcrypt = new_magic_crypt!(key, 256);
    let decrypted = mcrypt.decrypt_base64_to_string(data);
    match decrypted {
        Ok(decrypted) => return decrypt_slayer(KEY, decrypted.as_str()),
        Err(_) => return String::from(""),
    }
}

fn read_users() -> String {
    // read users.db file
    let mut file = File::open("users.db").expect("File not found");
    // read file contents
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Something went wrong reading the file");
    // print file contents
    contents = decrypt(KEY, &contents);
    return contents;
}

fn _parse_users_json() -> Users{
    let json = read_users();
    let deserialized_users: Users = serde_json::from_str(&json).unwrap();
    return deserialized_users;
}

fn add_new_user(username: &str, password: &str, uid: u128) -> ResponseStruct {
    assert!(username != "");
    assert!(password != "");
    assert!(uid != 0);
    // verify if user exists
    let users = _parse_users_json();
    for user in users.users_data {
        if user.username == username || user.uid == uid || unsafe{!IS_LIVE} {
            return ResponseStruct {
                status: String::from("[ERROR]"),
                message: String::from("User already exists")
            }
        }
    }
    let mut users = _parse_users_json();
    let new_user = User {
        username: username.to_string(),
        password: password.to_string(),
        uid: uid,
        personal_hash: compute_personal_hash(username, password, uid),
        balance: 0.0
    };
    users.users_data.push(new_user);
    let serialized_users = serde_json::to_string(&users).unwrap();
    println!("{}", serialized_users);
    // write to file
    let mut file = File::create("users.db").expect("File not found");
    file.write_all(encrypt(KEY,&serialized_users).as_bytes()).expect("Something went wrong writing the file");
    return ResponseStruct {
        status: String::from("[SUCCESS]"),
        message: String::from("User added successfully")
    }
}



fn _reset_database() {
    let mut file = File::create("users.db").expect("File not found");
    file.write_all(encrypt(KEY,"{\"users_data\":[]}").as_bytes()).expect("Something went wrong writing the file");
}

fn _encrypt_database() {
    let mut file = File::open("users.db").expect("File not found");
    // read file contents
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Something went wrong reading the file");
    // print file contents
    let mut file = File::create("users.db").expect("File not found");
    file.write_all(encrypt(KEY,&contents).as_bytes()).expect("Something went wrong writing the file");
}

fn  _decrypt_database() {
    let mut file = File::open("users.db").expect("File not found");
    // read file contents
    let mut contents = String::new();
    file.read_to_string(&mut contents).expect("Something went wrong reading the file");
    // print file contents
    let mut file = File::create("users.db").expect("File not found");
    file.write_all(decrypt(KEY,&contents).as_bytes()).expect("Something went wrong writing the file");
}

fn _print_database() {
    let users = _parse_users_json();
    for user in users.users_data {
        println!("Username: {}", user.username);
        println!("Password: {}", user.password);
        println!("UID: {}", user.uid);
        println!("Personal Hash: {}", user.personal_hash);
        println!("Balance: {}", user.balance);
        println!("\n---\n");
    }
}

fn _change_username(password: &str, uid: u128, old_username: &str, new_username: &str) -> ResponseStruct {
    assert!(old_username != "");
    assert!(new_username != "");
    let mut users = _parse_users_json();
    let mut user_exists = false;
    for user in users.users_data.iter_mut() {
        if user.username == old_username && user.password == password && user.uid == uid && user.personal_hash == compute_personal_hash(old_username, password, uid) {
            user_exists = true;
            user.username = new_username.to_string();
            user.personal_hash = compute_personal_hash(new_username, &user.password, user.uid);
        }
    }
    if user_exists {
        let serialized_users = serde_json::to_string(&users).unwrap();
        println!("{}", serialized_users);
        // write to file
        let mut file = File::create("users.db").expect("File not found");
        file.write_all(encrypt(KEY,&serialized_users).as_bytes()).expect("Something went wrong writing the file");
        return ResponseStruct {
            status: String::from("[SUCCESS]"),
            message: String::from("Username changed successfully")
        }
    } else {
        return ResponseStruct {
            status: String::from("[ERROR]"),
            message: String::from("User does not exist")
        }
    }
}

fn delete_user(username: &str, password: &str, uid: u128) -> ResponseStruct {
    assert!(username != "");
    assert!(password != "");
    assert!(uid != 0);
    let mut users = _parse_users_json();
    let mut user_exists = false;
    for user in users.users_data.iter_mut() {
        if user.username == username && user.password == password && user.uid == uid && user.personal_hash == compute_personal_hash(username, password, uid) {
            user_exists = true;
            user.username = String::from("");
            user.password = String::from("");
            user.uid = 0;
            user.personal_hash = String::from("");
            user.balance = 0.0;
        }
    }
    if user_exists {
        let serialized_users = serde_json::to_string(&users).unwrap();
        println!("{}", serialized_users);
        // write to file
        let mut file = File::create("users.db").expect("File not found");
        file.write_all(encrypt(KEY,&serialized_users).as_bytes()).expect("Something went wrong writing the file");
        return ResponseStruct {
            status: String::from("[SUCCESS]"),
            message: String::from("User deleted successfully")
        }
    } else {
        return ResponseStruct {
            status: String::from("[ERROR]"),
            message: String::from("User does not exist")
        }
    }
}

fn clean_empty_accounts() {
    let users = _parse_users_json();
    let mut new_users = Users {
        users_data: Vec::new()
    };
    for user in users.users_data {
        if user.username != "" && user.password != "" && user.uid != 0 && user.personal_hash == compute_personal_hash(&user.username, &user.password, user.uid) {
            new_users.users_data.push(user);
        }
    }
    let serialized_users = serde_json::to_string(&new_users).unwrap();
    // write to file
    let mut file = File::create("users.db").expect("File not found");
    file.write_all(encrypt(KEY,&serialized_users).as_bytes()).expect("Something went wrong writing the file");
}

fn handle_connection(mut stream: TcpStream) {
    let buf_reader = BufReader::new(&mut stream);
    let request_line = buf_reader.lines().next().unwrap().unwrap();
    let args = request_line.split_whitespace().collect::<Vec<&str>>();
    if args[1].contains("/undefined") {
        return;
    }
    if &args[1][..10] == "/add_user/" {
        {
            println!("Request: {:?}", args);
            let args = args[1][10..].split("?").collect::<Vec<&str>>();
            println!("Args: {:?}", args);
            let username = args[0];
            let password = args[1];
            let uid = args[2].parse::<u128>().unwrap();
            serde_json::to_writer(&stream, &add_new_user(username, password, uid))
        }
        .unwrap_or_else(|e| {
            println!("[ERROR]{}", e);
            serde_json::to_writer(&stream, &ResponseStruct {
                status: String::from("[ERROR]"),
                message: String::from("Error adding user -> ") + e.to_string().as_str()
            }).unwrap();
        });
        return;
    } else if &args[1][..13] == "/transaction/" {
    {   
        println!("Request: {:?}", args);
        let args = args[1][13..].split("?").collect::<Vec<&str>>();
        println!("Args: {:?}", args);
        let username_o = args[0];
        let password_o = args[1];
        let uid_o = args[2].parse::<u128>().unwrap();
        let username_t = args[3];
        let amount = args[4].parse::<f64>().unwrap();
        serde_json::to_writer(&stream, &_process_transaction(username_o, password_o, uid_o, username_t, amount))
    }
    .unwrap_or_else(|e| {
        println!("Error: {}", e);
        serde_json::to_writer(&stream, &ResponseStruct {
            status: String::from("[ERROR]"),
            message: String::from("Error processing transaction -> ") + e.to_string().as_str()
        }).unwrap();
    });
        return;
    } else if &args[1][..17] == "/change_username/" {
        {
            println!("Request: {:?}", args);
            let args = args[1][17..].split("?").collect::<Vec<&str>>();
            println!("Args: {:?}", args);
            let password = args[0];
            let uid = args[1].parse::<u128>().unwrap();
            let old_username = args[2];
            let new_username = args[3];
            serde_json::to_writer(&stream, &_change_username(password, uid, old_username, new_username))
        }
        .unwrap_or_else(|e| {
            println!("[ERROR]{}", e);
            serde_json::to_writer(&stream, &ResponseStruct {
                status: String::from("[ERROR]"),
                message: String::from("Error changing username -> ") + e.to_string().as_str()
            }).unwrap();
        });
        return;
    }
}

fn main() {
    // _print_database();
    if unsafe {IS_LIVE} {
        _print_database();
        println!("Starting server...");
        let listener = TcpListener::bind("127.0.0.1:7979").unwrap();
        println!("Server started on port 7979");
        let thread_pool = ThreadPool::new(10);
        for stream in listener.incoming() {
            let stream = stream.unwrap();
            thread_pool.execute(|| {
                handle_connection(stream);
            });
        }
    }
}

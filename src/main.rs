use std::{fs::{File}, io::{Read, Write, BufReader, BufRead}, net::TcpStream};
use magic_crypt::{new_magic_crypt, MagicCryptTrait};
use serde::{Serialize, Deserialize};
use sha2::{Digest, Sha512_256, Sha224, Sha512_224};
use threadpool::ThreadPool;
use transactions::_process_transaction;
use std::net::TcpListener;
mod transactions;
use try_catch::catch;

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

fn read_users() -> Users {
    // read all .db files in the db folder and concat them in a vector
    let mut users: Vec<User> = Vec::new();
    let files = std::fs::read_dir("data").unwrap();
    for file in files {
        let file = file.unwrap();
        let path = file.path();
        let path_str = path.to_str().unwrap();
        if path_str.ends_with(".db") {
            let mut file = File::open(path_str).unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap();
            contents = decrypt(KEY, contents.as_str());
            let user: User = serde_json::from_str(&contents).unwrap();
            users.push(user);
        }
    }
    let users_struct = Users {
        users_data: users
    };
    let users_json = users_struct;
    return users_json
}

fn add_new_user(username: &str, password: &str, uid: u128) -> ResponseStruct {
    // create new user file in the db folder
    let users = read_users();
    let mut user_exists = false;
    for user in users.users_data.iter() {
        if user.username == username {
            user_exists = true;
        }
    }
    if user_exists {
        return ResponseStruct {
            status: String::from("ERROR"),
            message: String::from("User already exists")
        }
    }
    let personal_hash = compute_personal_hash(username, password, uid);
    let new_user = User {
        username: String::from(username),
        password: String::from(password),
        uid: uid,
        personal_hash: personal_hash,
        balance: 0.0
    };
    let users_json = serde_json::to_string(&new_user).unwrap();
    let mut file = File::create(format!("data/{}.db", encrypt(KEY, username))).unwrap();
    file.write_all(encrypt(KEY, &users_json).as_bytes()).unwrap();
    return ResponseStruct {
        status: String::from("SUCCESS"),
        message: String::from("User created")
    }
}

fn add_admin() {
    let users = read_users();
    let mut admin_exists = false;
    for user in users.users_data.iter() {
        if user.username == "admin" {
            admin_exists = true;
        }
    }
    if !admin_exists {
        let personal_hash = compute_personal_hash("admin", "admin", 11111111111111111111111111111111);
        let new_user = User {
            username: String::from("admin"),
            password: String::from("admin"),
            uid: 11111111111111111111111111111111,
            personal_hash: personal_hash,
            balance: 50000.0
        };
        let users_json = serde_json::to_string(&new_user).unwrap();
        let mut file = File::create(format!("data/{}.db", encrypt(KEY, "admin"))).unwrap();
        file.write_all(encrypt(KEY, &users_json).as_bytes()).unwrap();
    }
}


fn _reset_database() {
    // delete all .db files in the db folder
    let files = std::fs::read_dir("data").unwrap();
    for file in files {
        let file = file.unwrap();
        let path = file.path();
        let path_str = path.to_str().unwrap();
        if path_str.ends_with(".db") {
            std::fs::remove_file(path_str).unwrap();
        }
    }
}

fn _encrypt_database() {
    // encrypt all .db files in the db folder
    let files = std::fs::read_dir("data").unwrap();
    for file in files {
        let file = file.unwrap();
        let path = file.path();
        let path_str = path.to_str().unwrap();
        if path_str.ends_with(".db") {
            let mut file = File::open(path_str).unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap();
            let encrypted = encrypt(KEY, &contents);
            let mut file = File::create(path_str).unwrap();
            file.write_all(encrypted.as_bytes()).unwrap();
        }
    }
}

fn  _decrypt_database() {
    // decrypt all .db files in the db folder
    let files = std::fs::read_dir("data").unwrap();
    for file in files {
        let file = file.unwrap();
        let path = file.path();
        let path_str = path.to_str().unwrap();
        if path_str.ends_with(".db") {
            let mut file = File::open(path_str).unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap();
            let decrypted = decrypt(KEY, &contents);
            let mut file = File::create(path_str).unwrap();
            file.write_all(decrypted.as_bytes()).unwrap();
        }
    }
}

fn _print_database() {
    // print all .db files in the db folder
    let users = read_users();
    // print all users nicely
    println!("---------------------");
    for user in users.users_data.iter() {
        println!("Username: {}", user.username);
        println!("Password: {}", user.password);
        println!("UID: {}", user.uid);
        println!("Personal hash: {}", user.personal_hash);
        println!("Balance: {}", user.balance);
        println!("---------------------");
    }
}

fn _change_username(password: &str, uid: u128, old_username: &str, new_username: &str) -> ResponseStruct {
    // change username of a user
    let users = read_users();
    let mut user_exists = false;
    let mut user_index = 0;
    for (index, user) in users.users_data.iter().enumerate() {
        if user.username == old_username {
            user_exists = true;
            user_index = index;
        }
    }
    if !user_exists {
        return ResponseStruct {
            status: String::from("ERROR"),
            message: String::from("User does not exist")
        }
    }
    let user = users.users_data.get(user_index).unwrap();
    if user.password != password || user.uid != uid {
        return ResponseStruct {
            status: String::from("ERROR"),
            message: String::from("Wrong password or UID")
        }
    }
    let personal_hash = compute_personal_hash(new_username, password, uid);
    let new_user = User {
        username: String::from(new_username),
        password: String::from(password),
        uid: uid,
        personal_hash: personal_hash,
        balance: user.balance
    };
    let users_json = serde_json::to_string(&new_user).unwrap();
    let mut file = File::create(format!("data/{}.db", encrypt(KEY, new_username))).unwrap();
    file.write_all(encrypt(KEY, &users_json).as_bytes()).unwrap();
    std::fs::remove_file(format!("data/{}.db", encrypt(KEY, old_username))).unwrap();
    return ResponseStruct {
        status: String::from("SUCCESS"),
        message: String::from("Username changed")
    }
}

fn _delete_user(username: &str, password: &str, uid: u128) -> ResponseStruct {
    // delete a user
    let users = read_users();
    let mut user_exists = false;
    let mut user_index = 0;
    for (index, user) in users.users_data.iter().enumerate() {
        if user.username == username {
            user_exists = true;
            user_index = index;
        }
    }
    if !user_exists {
        return ResponseStruct {
            status: String::from("ERROR"),
            message: String::from("User does not exist")
        }
    }
    let user = users.users_data.get(user_index).unwrap();
    if user.password != password || user.uid != uid {
        return ResponseStruct {
            status: String::from("ERROR"),
            message: String::from("Wrong password or UID")
        }
    }
    std::fs::remove_file(format!("data/{}.db", encrypt(KEY, username))).unwrap();
    return ResponseStruct {
        status: String::from("SUCCESS"),
        message: String::from("User deleted")
    }
}

fn _clean_empty_accounts() {
    // delete all empty accounts
    let users = read_users();
    let mut user_exists = false;
    let mut user_index = 0;
    for (index, user) in users.users_data.iter().enumerate() {
        if user.balance == 0.0 {
            user_exists = true;
            user_index = index;
        }
    }
    if !user_exists {
        return;
    }
    let user = users.users_data.get(user_index).unwrap();
    std::fs::remove_file(format!("data/{}.db", encrypt(KEY, &user.username))).unwrap();
    _clean_empty_accounts();
}

fn handle_connection(mut stream: TcpStream) {
    let buf_reader = BufReader::new(&mut stream);
    let request_line = buf_reader.lines().next().expect("[ERROR.THREADPOOL_REQUEST_LINE]").expect("[ERROR.THREADPOOL_REQUEST_LINE]");
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
            println!("ERROR{}", e);
            serde_json::to_writer(&stream, &ResponseStruct {
                status: String::from("ERROR"),
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
            status: String::from("ERROR"),
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
            println!("ERROR{}", e);
            serde_json::to_writer(&stream, &ResponseStruct {
                status: String::from("ERROR"),
                message: String::from("Error changing username -> ") + e.to_string().as_str()
            }).unwrap();
        });
        return;
    }
}

fn main() {
    if unsafe {IS_LIVE} {
        _print_database();
        println!("Starting server...");
        let listener = TcpListener::bind("127.0.0.1:7979").unwrap();
        println!("Server started on port 7979");
        let thread_pool = ThreadPool::new(10);
        for stream in listener.incoming() {
            catch! {
                try {
                    let stream = stream.unwrap();
                    thread_pool.execute(|| {
                        handle_connection(stream);
                    });
                } 
                catch _error {
                    println!("[ERROR.THREADPOOL_CONNECTION_HANDLING]");
                }
            }
        }
    }
}

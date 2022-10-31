use std::io::Read;
use std::net::TcpStream;
use std::fs::File;
use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use lib::hash::encrypt_data;
use lib::hash::decrypt_data;
use serde::Serialize;
use serde::Deserialize;
use sha2::Digest;
use sha2::Sha512_256;
use sha2::Sha512_224;
use sha2::Sha224;
use threadpool::ThreadPool;
use transactions::_process_transaction;
use std::net::TcpListener;
mod transactions;
mod lib { pub mod hash; }
use try_catch::catch;
use std::str;


// GLOBALS
static mut IS_LIVE: bool = true;
static KEY: &str = "d7b27ab68a4271dab68ab68ab68ab68e5ab6832e1b2965fc04fea48ac6adb7da547b27";
static mut AVAILABLE_THREADS: u8 = 9;
static mut WAITING_LIST: Vec<TcpStream> = Vec::new();
static mut THREADS: Threads = Threads {
    threads: Vec::new()
};




#[derive(Serialize, Deserialize, Debug)]
pub struct Thread {
    available_functions: u16
}


#[derive(Serialize, Deserialize, Debug)]
pub struct Threads {
    threads: Vec<Thread>
}


/// Properties:
/// * `username`: The username of the user
/// * `password`: The password of the user.
/// * `uid`: A unique identifier for the user.
/// * `personal_hash`: A hash of the user's username, password, and uid.
/// * `balance`: The amount of money the user has
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


/// 
/// 
/// Properties:
/// 
/// * `status`: This is the status of the response. It can be either success or error.
/// * `message`: The message to be displayed to the user.
#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseStruct {
    status: String,
    message: String
}



fn compute_personal_hash(username: &str, password: &str, uid: u128) -> String {
    // create the 'hashers', and hash the data
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


// fn encrypt_data(data: &str) -> String {
//     let mcrypt = new_magic_crypt!(KEY, 256);
//     let mut encrypt_dataed = mcrypt.encrypt_data_str_to_base64(data);
//     encrypt_dataed = mcrypt.encrypt_data_str_to_base64(encrypt_dataed.as_str());
//     return encrypt_dataed;
// }

// fn decrypt_data(data: &str) -> String {
//     let mcrypt = new_magic_crypt!(KEY, 256);
//     let decrypt_dataed = mcrypt.decrypt_data_base64_to_string(data);
//     match decrypt_dataed {
//         Ok(decrypt_dataed) => {
//             let decrypt_dataed_layer_two = mcrypt.decrypt_data_base64_to_string(decrypt_dataed.as_str());
//             match decrypt_dataed_layer_two {
//                 Ok(decrypt_dataed_layer_two) => return decrypt_dataed_layer_two,
//                 Err(_) => return String::from(""),
//             }
//         },
//         Err(_) => return String::from(""),
//     }
// }

fn read_users() -> Users {
    // read all .db files in the db folder and concat them in a vector
    let mut users: Vec<User> = Vec::new();
    // read the db folder and get a list of all the files
    let files = std::fs::read_dir("data").unwrap();
    for file in files {
        let file = file.unwrap();
        let path = file.path();
        let path_str = path.to_str().unwrap();
        // ignore non .db files
        if path_str.ends_with(".db") {
            // read the file, and deserialize/decrypt it
            let mut file = File::open(path_str).unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap();
            contents = decrypt_data(&contents);
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



/// It creates a new user file in the db folder
/// 
/// Arguments:
/// 
/// * `username`: &str, password: &str, uid: u128
/// * `password`: &str,
/// * `uid`: u128
/// 
/// Returns:
/// 
/// A ResponseStruct
fn add_new_user(username: &str, password: &str, uid: u128) -> ResponseStruct {
    // create new user file in the db folder
    let users = read_users();
    let mut user_exists = false;
    // check if the user already exists
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
    // create the user struct and serialize it, then encrypt it and write it to the file
    let personal_hash = compute_personal_hash(username, password, uid);
    let new_user = User {
        username: String::from(username),
        password: String::from(password),
        uid: uid,
        personal_hash: personal_hash,
        balance: 0.0
    };
    let users_json = serde_json::to_string(&new_user).unwrap();
    println!("{}", format!("data/{}.db", base64_url::encode(username)));
    let mut file = File::create(format!("data/{}.db", base64_url::encode(username))).unwrap();
    file.write_all(encrypt_data(&users_json).as_bytes()).unwrap();
    return ResponseStruct {
        status: String::from("SUCCESS"),
        message: String::from("User created")
    }
}



fn _add_admin() {
    // check if the admin exists
    let users = read_users();
    let mut admin_exists = false;
    for user in users.users_data.iter() {
        if user.username == "admin" {
            admin_exists = true;
        }
    }
    // if it doesn't exist, create it, seralize it, encrypt it, and write it to the file
    if !admin_exists {
        let personal_hash = compute_personal_hash("admin", "admin", 011);
        let new_user = User {
            username: String::from("admin"),
            password: String::from("admin"),
            uid: 011,
            personal_hash: personal_hash,
            balance: 500000.0
        };
        let users_json = serde_json::to_string(&new_user).unwrap();
        println!("{}", format!("data/{}.db", base64_url::encode("admin")));
        let mut file = File::create(format!("data/{}.db", base64_url::encode("admin"))).unwrap();
        file.write_all(encrypt_data(&users_json).as_bytes()).unwrap();
    }
}



fn _reset_database() {
    // delete all .db files in the data folder
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
    // encrypt_data all .db files in the db folder
    let files = std::fs::read_dir("data").unwrap();
    for file in files {
        let file = file.unwrap();
        let path = file.path();
        let path_str = path.to_str().unwrap();
        if path_str.ends_with(".db") {
            let mut file = File::open(path_str).unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap();
            let encrypted = encrypt_data(&contents);
            let mut file = File::create(path_str).unwrap();
            file.write_all(encrypted.as_bytes()).unwrap();
        }
    }
}



fn  _decrypt_database() {
    // decrypt_data all .db files in the db folder
    let files = std::fs::read_dir("data").unwrap();
    for file in files {
        let file = file.unwrap();
        let path = file.path();
        let path_str = path.to_str().unwrap();
        if path_str.ends_with(".db") {
            let mut file = File::open(path_str).unwrap();
            let mut contents = String::new();
            file.read_to_string(&mut contents).unwrap();
            let decrypted = str::from_utf8(&decrypt_data(&contents).as_bytes()).unwrap().to_string();
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



/// It takes a password, a user ID, an old username, and a new username, and if the password and user ID
/// are correct, it changes the username
/// 
/// Arguments:
/// 
/// * `password`: &str, uid: u128, old_username: &str, new_username: &str
/// * `uid`: The user's unique ID
/// * `old_username`: The username of the user who wants to change their username
/// * `new_username`: The new username
/// 
/// Returns:
/// 
/// A ResponseStruct
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
    let mut file = File::create(format!("data/{}.db", encrypt_data(new_username))).unwrap();
    file.write_all(encrypt_data(&users_json).as_bytes()).unwrap();
    std::fs::remove_file(format!("data/{}.db", encrypt_data(old_username))).unwrap();
    return ResponseStruct {
        status: String::from("SUCCESS"),
        message: String::from("Username changed")
    }
}



/// It deletes a user
/// 
/// Arguments:
/// 
/// * `username`: The username of the user to delete
/// * `password`: The password of the user
/// * `uid`: The user's unique ID
/// 
/// Returns:
/// 
/// A ResponseStruct
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
    if user.password != password || user.uid != uid || compute_personal_hash(username, password, uid) != user.personal_hash {
        return ResponseStruct {
            status: String::from("ERROR"),
            message: String::from("Wrong password or UID")
        }
    }
    std::fs::remove_file(format!("data/{}.db", base64_url::encode(username))).unwrap();
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
    std::fs::remove_file(format!("data/{}.db", encrypt_data(&user.username))).unwrap();
    _clean_empty_accounts();
}



/// It takes a username, old password, uid, and new password, and returns a response struct
/// 
/// Arguments:
/// 
/// * `username`: username of the user
/// * `old_password`: The old password of the user
/// * `uid`: u128,
/// * `new_password`: The new password
/// 
/// Returns:
/// 
/// A ResponseStruct
fn _change_password(username: &str, old_password: &str, uid: u128, new_password: &str) -> ResponseStruct {
    // change password of a user
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
    if user.password != old_password || user.uid != uid {
        return ResponseStruct {
            status: String::from("ERROR"),
            message: String::from("Wrong password or UID")
        }
    }
    let personal_hash = compute_personal_hash(username, new_password, uid);
    let new_user = User {
        username: String::from(username),
        password: String::from(new_password),
        uid: uid,
        personal_hash: personal_hash,
        balance: user.balance
    };
    let users_json = serde_json::to_string(&new_user).unwrap();
    let mut file = File::create(format!("data/{}.db", encrypt_data(username))).unwrap();
    file.write_all(encrypt_data(&users_json).as_bytes()).unwrap();
    return ResponseStruct {
        status: String::from("SUCCESS"),
        message: String::from("Password changed")
    }
}



/// It reads the users from a file, checks if the user exists, checks if the password and UID are
/// correct, and if they are, returns the balance
/// 
/// Arguments:
/// 
/// * `username`: &str, password: &str, uid: u128
/// * `password`: The password of the user
/// * `uid`: The user's unique ID
/// 
/// Returns:
/// 
/// A ResponseStruct
fn _get_balance(username: &str, password: &str, uid: u128) -> ResponseStruct {
    // get balance of a user
    let users = read_users();
    let mut user_exists = false;
    let mut user_index = 0;
    for (index, user) in users.users_data.iter().enumerate() {
        println!("{} {}", user.username, username);
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
    return ResponseStruct {
        status: String::from("SUCCESS"),
        message: format!("Balance: {}", user.balance)
    }
}



/// It takes a TCP stream, reads the first line of the request, splits it into a vector, and then checks
/// if the request is one of the following:
/// 
/// /add_user/
/// /transaction/
/// /change_username/
/// /change_password/
/// /delete_user/
/// /get_balance/
/// 
/// If it is, it splits the request into a vector again, and then calls the appropriate function
/// 
/// Arguments:
/// 
/// * `stream`: TcpStream
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
    } else if &args[1][..17] == "/change_password/" {
        {
            println!("Request: {:?}", args);
            let args = args[1][17..].split("?").collect::<Vec<&str>>();
            println!("Args: {:?}", args);
            let username = args[0];
            let password = args[1];
            let uid = args[2].parse::<u128>().unwrap();
            let new_password = args[3];
            serde_json::to_writer(&stream, &_change_password(username, password, uid, new_password))
        }
        .unwrap_or_else(|e| {
            println!("ERROR{}", e);
            serde_json::to_writer(&stream, &ResponseStruct {
                status: String::from("ERROR"),
                message: String::from("Error changing password -> ") + e.to_string().as_str()
            }).unwrap();
        });
        return;
    } else if &args[1][..13] == "/delete_user/" {
        {
            println!("Request: {:?}", args);
            let args = args[1][13..].split("?").collect::<Vec<&str>>();
            println!("Args: {:?}", args);
            let username = args[0];
            let password = args[1];
            let uid = args[2].parse::<u128>().unwrap();
            serde_json::to_writer(&stream, &_delete_user(username, password, uid))
        }
        .unwrap_or_else(|e| {
            println!("ERROR{}", e);
            serde_json::to_writer(&stream, &ResponseStruct {
                status: String::from("ERROR"),
                message: String::from("Error deleting user -> ") + e.to_string().as_str()
            }).unwrap();
        });
        return;
    } else if &args[1][..13] == "/get_balance/" {
        {
            println!("Request: {:?}", args);
            let args = args[1][13..].split("?").collect::<Vec<&str>>();
            println!("Args: {:?}", args);
            let username = args[0];
            let password = args[1];
            let uid = args[2].parse::<u128>().unwrap();
            println!("{:?}", &_get_balance(username, password, uid));
            serde_json::to_writer(&stream, &_get_balance(username, password, uid))
        }
        .unwrap_or_else(|e| {
            println!("ERROR{}", e);
            serde_json::to_writer(&stream, &ResponseStruct {
                status: String::from("ERROR"),
                message: String::from("Error getting balance -> ") + e.to_string().as_str()
            }).unwrap();
        });
    }
}



fn populate_threads() {
    unsafe {
        let mut threads: Vec<Thread> = Vec::new();
        for _ in 0..AVAILABLE_THREADS {
            threads.push(Thread {
                available_functions: 10
            });
        }
        THREADS.threads = threads;
}}


fn handle_waiting_list(thread_pool: ThreadPool) {
    unsafe {
        if WAITING_LIST.len() > 0 {
            for i in 0..THREADS.threads.len() {
                if THREADS.threads[i].available_functions > 0 {
                    THREADS.threads[i].available_functions -= 1;
                    // let mut thread = thread::spawn(move || {
                    //     let mut stream = WAITING_LIST[0].stream;
                    //     let mut args = WAITING_LIST[0].args;
                    //     WAITING_LIST.remove(0);
                    //     handle_request(&mut stream, &mut args);
                    //     THREADS.threads[i].available_functions += 1;
                    // });
                    // thread.join().unwrap();
                    thread_pool.execute(move || {
                        handle_connection(WAITING_LIST[0].try_clone().unwrap());
                        WAITING_LIST.remove(0);
                        THREADS.threads[i].available_functions += 1;
                    });
                }
            }
        }
    }
}

/// It starts a server on port 443, and then for each connection it receives, it spawns a new thread to
/// handle the connection.
fn main() {
    if unsafe {IS_LIVE} {
        _print_database();
        println!("Starting server...");
        let listener = TcpListener::bind("127.0.0.1:443").unwrap();
        println!("Server started on port 443");
        let thread_pool = ThreadPool::new(10);
        populate_threads();
        for stream in listener.incoming() {
            if (unsafe {WAITING_LIST.len()} as u16) < (unsafe {AVAILABLE_THREADS as u16} * 10) {
                catch! {
                try {
                    if unsafe{IS_LIVE} {
                        let stream = stream.unwrap();
                        thread_pool.execute(|| {
                            handle_connection(stream);
                        });
                    }
                } 
                catch _error {
                    println!("[ERROR.THREADPOOL_CONNECTION_HANDLING]");
                }
            }
            } else {
                let stream = stream.unwrap();
            // inform the user that the server is busy
            if true {
                let mut stream = stream;
                let response = ResponseStruct {
                    status: String::from("..."),
                    message: String::from("Your request is being processed, please wait...")
                };
                serde_json::to_writer(&mut stream, &response).unwrap();
                continue;
            }
            unsafe {
                WAITING_LIST.push(stream.try_clone().unwrap());
            }
            handle_waiting_list(thread_pool.clone());
            }
        
            // catch! {
            //     try {
            //         if unsafe{IS_LIVE} {
            //             let stream = stream.unwrap();
            //             thread_pool.execute(|| {
            //                 handle_connection(stream);
            //             });
            //         }
            //     } 
            //     catch _error {
            //         println!("[ERROR.THREADPOOL_CONNECTION_HANDLING]");
            //     }
            // }
        }
    }
}
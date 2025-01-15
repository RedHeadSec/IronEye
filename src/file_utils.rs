use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub fn load_userlist(file_path: &str) -> io::Result<Vec<String>> {
    let path = Path::new(file_path);
    let file = File::open(path)?;
    let reader = io::BufReader::new(file);
    let users: Vec<String> = reader.lines()
        .filter_map(|line| line.ok())
        .collect();
    Ok(users)
}
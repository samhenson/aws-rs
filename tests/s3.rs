// Copyright (C) 2015 Sam Henson
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#![feature(convert)]
#![feature(slice_patterns)]

extern crate aws;
extern crate rand;
extern crate tempdir;

use std::env;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use tempdir::TempDir;

use rand::Rng;

fn get_s3_path () -> String {
    match env::var("AWS_LIB_TEST_S3_PATH") {
        Ok(s)  => return s,
        Err(_) => panic!("AWS_LIB_TEST_S3_PATH is not defined")
    }
}

fn write_random_data (p : &Path) {
    let mut rnd = rand::OsRng::new().unwrap();
    let mut f = File::create(p).unwrap();
    let data : Vec<u8> = rnd.gen_iter().take(102400).collect();
    f.write(&data).unwrap();
}

fn read_from_file (p : &Path) -> Vec<u8> {
    let mut f = File::open(p).unwrap();
    let mut data : Vec<u8> = Vec::new();
    f.read_to_end(&mut data).unwrap();
    data
}

#[test]
fn round_trip () {
    let tmp_dir = TempDir::new("rust-test").unwrap();

    let mut src_file = PathBuf::from(tmp_dir.path());

    src_file.push("test_data_send.bin");

    let unparsed_path = get_s3_path();
    let parts : Vec<&str> = unparsed_path.splitn(2, '/').collect();
    let (s3_bucket, mut s3_path) : (String, String) = match parts.as_slice() {
        [bucket]       => (bucket.to_string(), "/".to_string()),
        [bucket, path] => (bucket.to_string(), "/".to_string() + path),
        _              => panic!("Error parsing s3 path")
    };
    s3_path = s3_path + "/test_data.bin";

    println!("Using {} {}", s3_bucket, s3_path);

    write_random_data(&src_file);
    aws::s3::put(&s3_bucket, &s3_path, &src_file, & vec![]).unwrap();

    let data1 = read_from_file(&src_file);
    let data2 = aws::s3::get(&s3_bucket, &s3_path).unwrap();

    assert!(data1 == data2);
}


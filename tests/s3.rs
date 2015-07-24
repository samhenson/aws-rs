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
use std::path::Path;
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

fn write_json_data (p : &Path) {
    let mut f = File::create(p).unwrap();
    let data = "{ \"test_key\": \"test_value\" }".to_string();
    f.write(data.as_bytes()).unwrap();
}

fn read_from_file (p : &Path) -> Vec<u8> {
    let mut f = File::open(p).unwrap();
    let mut data : Vec<u8> = Vec::new();
    f.read_to_end(&mut data).unwrap();
    data
}

fn s3_path_parts () -> (String, String) {
    let unparsed_path = get_s3_path();
    let parts : Vec<&str> = unparsed_path.splitn(2, '/').collect();
    match parts.as_slice() {
        [bucket]       => (bucket.to_string(), "/".to_string()),
        [bucket, path] => (bucket.to_string(), "/".to_string() + path),
        _              => panic!("Error parsing s3 path")
    }
}

#[test]
fn round_trip () {
    let tmp_dir = TempDir::new("rust-test").unwrap();
    let src_file = tmp_dir.path().join("test_data_send.bin");

    let (s3_bucket, mut s3_path) = s3_path_parts();
    s3_path = s3_path + "/test_data_1.bin";

    println!("Using {} {}", s3_bucket, s3_path);

    write_random_data(&src_file);
    aws::s3::put(&s3_bucket, &s3_path, &src_file, & vec![]).unwrap();

    let data1 = read_from_file(&src_file);
    let data2 = aws::s3::get(&s3_bucket, &s3_path).unwrap();

    assert!(data1 == data2);
}

#[test]
fn content_type () {
    let tmp_dir = TempDir::new("rust-test").unwrap();
    let src_file = tmp_dir.path().join("test_data.json");

    let (s3_bucket, mut s3_path) = s3_path_parts();
    s3_path = s3_path + "/test_data_2.bin";

    write_json_data(&src_file);
    aws::s3::put(&s3_bucket, &s3_path, &src_file, & vec![ ("Content-Type", "application/json" ) ]).unwrap();

    let headers = aws::s3::head(&s3_bucket, &s3_path).unwrap();
    match headers.get("content-type") {
        Some(values) => assert!(values[0] == "application/json"),
        None         => panic!("No Content-Type header")
    }
}


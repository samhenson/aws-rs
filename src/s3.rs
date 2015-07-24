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

use std::io;
use std::str::from_utf8;
use std::collections::HashMap;
use std::fmt;
use std::env;
use std::fs::File;

use std::path::{Path, PathBuf};
use std::ascii::AsciiExt;

use std::io::Read;

use crypto;
use time;
use xml;

use curl::http;
use crypto::mac::Mac;
use crypto::digest::Digest;
use rustc_serialize::hex::ToHex;


// ---------------------------------------------------------------------------------------------------------------------

fn aws_access_key_id () -> String {
    match env::var("AWS_ACCESS_KEY_ID") {
        Ok(s)  => return s,
        Err(_) => panic!("AWS_ACCESS_KEY_ID is not defined")
    }
}

fn aws_secret_access_key () -> String {
    match env::var("AWS_SECRET_ACCESS_KEY") {
        Ok(s)  => return s,
        Err(_) => panic!("AWS_SECRET_ACCESS_KEY is not defined")
    }
}

// ---------------------------------------------------------------------------------------------------------------------

fn sha256 (data : &[u8]) -> String {
    let mut hash = crypto::sha2::Sha256::new();
    hash.input(data);
    hash.result_str()
}

fn hmac_sha256 (secret : &[u8], data : &[u8]) -> Vec<u8> {
    let mut hmac = crypto::hmac::Hmac::new(crypto::sha2::Sha256::new(), secret);
    hmac.input(data);
    hmac.result().code().to_vec()
}

fn date (fmt : &str) -> String {
    time::strftime(fmt, &time::now_utc()).unwrap()
}

// ---------------------------------------------------------------------------------------------------------------------

#[derive (Clone,Copy,Debug)]
enum AwsRegion {
    UsEast1,
    UsWest1,
    UsWest2,
    EuWest1,
    EuCentral1,
    ApSoutheast1,
    ApSoutheast2,
    ApNortheast1,
    SaEast1
}

fn str_to_region (s : &str) -> AwsRegion {
    match s {
        ""               => AwsRegion::UsEast1,
        "us-east-1"      => AwsRegion::UsEast1,
        "us-west-1"      => AwsRegion::UsWest1,
        "us-west-2"      => AwsRegion::UsWest2,
        "eu-west-1"      => AwsRegion::EuWest1,
        "eu-central-1"   => AwsRegion::EuCentral1,
        "ap-southeast-1" => AwsRegion::ApSoutheast1,
        "ap-southeast-2" => AwsRegion::ApSoutheast2,
        "ap-northeast-1" => AwsRegion::ApNortheast1,
        "sa-east-1"      => AwsRegion::SaEast1,
        unknown          => panic!("Unknown S3 region {}", unknown)
    }
}

fn region_str (region : AwsRegion) -> &'static str {
    match region {
        AwsRegion::UsEast1      => "us-east-1",
        AwsRegion::UsWest1      => "us-west-1",
        AwsRegion::UsWest2      => "us-west-2",
        AwsRegion::EuWest1      => "eu-west-1",
        AwsRegion::EuCentral1   => "eu-central-1",
        AwsRegion::ApSoutheast1 => "ap-southeast-1",
        AwsRegion::ApSoutheast2 => "ap-southeast-2",
        AwsRegion::ApNortheast1 => "ap-northeast-1",
        AwsRegion::SaEast1      => "sa-east-1"
    }
}

fn s3_endpoint (region : AwsRegion) -> &'static str {
    match region {
        AwsRegion::UsEast1      => "s3-external-1.amazonaws.com",
        AwsRegion::UsWest1      => "s3-us-west-1.amazonaws.com",
        AwsRegion::UsWest2      => "s3-us-west-2.amazonaws.com",
        AwsRegion::EuWest1      => "s3-eu-west-1.amazonaws.com",
        AwsRegion::EuCentral1   => "s3-eu-central-1.amazonaws.com",
        AwsRegion::ApSoutheast1 => "s3-ap-southeast-1.amazonaws.com",
        AwsRegion::ApSoutheast2 => "s3-ap-southeast-2.amazonaws.com",
        AwsRegion::ApNortheast1 => "s3-ap-northeast-1.amazonaws.com",
        AwsRegion::SaEast1      => "s3-sa-east-1.amazonaws.com"
    }
}

fn aws_signing_key (region : AwsRegion, service : &str, key_date : &str) -> Vec<u8> {
    let key_str   : String  = format!("AWS4{}", aws_secret_access_key());
    let w_date    : Vec<u8> = hmac_sha256( key_str.as_bytes(), key_date.as_bytes() );
    let w_region  : Vec<u8> = hmac_sha256( &w_date, region_str(region).as_bytes() );
    let w_service : Vec<u8> = hmac_sha256( &w_region, service.as_bytes());
    hmac_sha256( &w_service, "aws4_request".as_bytes())
}

fn uri_encode_char (c : u8, encode_slash : bool) -> String {
    if (c >= b'A' && c <= b'Z') || (c >= b'a' && c <= b'z') || (c >= b'0' && c <= b'9') ||
       (c == b'_') || (c == b'-') || (c == b'~') || (c == b'.') {
        from_utf8(&vec![c]).unwrap().to_string()
    } else if c == b'/' {
      if encode_slash { "%2F".to_string() } else { from_utf8(&vec![c]).unwrap().to_string() }
    } else {
        format!("%{:X}", c)
    } 
}

fn uri_encode (s : &str, encode_slash : bool) -> String {
    let strs : Vec<String> = s.bytes().map( |c| uri_encode_char(c, encode_slash) ).collect();
    strs.concat()
}

fn header_is_set (headers: &[(&str, &str)], name : &str) -> bool {
    for h in headers.iter() {
        if h.0 == name {
            return true;
        }
    }
    false
}

fn aws_s3_request (method: &HttpMethod, region: AwsRegion, host: &str, uri: &str, query_str: &str, headers: &[(&str, &str)]) -> io::Result<http::Response> {

    // ----

    let mut body : Vec<u8> = Vec::new();

    match method {
        &HttpMethod::Put(ref f) => {
            try!( try!(File::open(f)).read_to_end(&mut body) );
        },
        _ => {}
    }

    let request_time : String = date("%Y%m%dT%H%M%SZ");
    let request_date : &str   = &request_time[0..8];
    let content_hash : String = sha256(&body);

    // ----

    let fixed_uri : String = if uri.starts_with("/") {
        uri.to_string()
    } else {
        "/".to_string() + uri
    };

    let url = if query_str.len() > 0 {
        format!("https://{}{}?{}", host, fixed_uri, query_str)
    } else {
        format!("https://{}{}", host, fixed_uri)
    };

    let mut connection = http::handle().timeout(600_000);
    let mut request = match method {
        &HttpMethod::Head   => connection.head(url),
        &HttpMethod::Get    => connection.get(url),
        &HttpMethod::Put(_) => connection.put(url, &body[..])
    };

    // ----

    let mut all_headers : Vec<(&str, &str)> = Vec::new();
    all_headers.push(("Host", host));
    all_headers.push(("Date", &request_time));

    if ! header_is_set(headers, "Content-Type") {
        all_headers.push(("Content-Type", "application/octet-stream"));
    }

    all_headers.push(("x-amz-content-sha256", &content_hash));

    for h in headers.iter() {
        let (name, value) = *h;
        all_headers.push((name, value));
    }

    for h in all_headers.iter() {
        let (name, value) = *h;
        request = request.header(name, value);
    }

    // ----

    let mut query : Vec<(String, String)> = Vec::new();
    for q in query_str.split('&') {
        let parts : Vec<&str> = q.splitn(1, '=').collect();
        match parts.len() {
            0 => { },
            1 => {
                match parts[0] {
                    ""   => { },
                    name => { query.push((uri_encode(name, true), String::new())); }
                }
            },
            _ => { query.push((uri_encode(parts[0], true), uri_encode(parts[1], true))); }
        }
    }

    // ----

    let mut header_list : Vec<(String, String)> = Vec::new();
    let mut header_names : Vec<String> = Vec::new();
    for h in all_headers.iter() {
        let (name, value) = *h;
        header_list.push((name.to_string().to_ascii_lowercase(), value.trim().to_string()));
        header_names.push(name.to_string().to_ascii_lowercase());
    }
    header_list.sort_by(|a,b| a.0.cmp(&b.0));
    header_names.sort();
    let canonical_headers_l : Vec<String> = header_list.into_iter().map(|(n,v)| n + ":" + &v + "\n" ).collect();
    let canonical_headers = canonical_headers_l.concat();
    let signed_headers = header_names.connect(";");

    // ----

    query.sort_by(|a,b| a.0.cmp(&b.0));
    let query_strings : Vec<String> = query.into_iter().map(|(n,v)| n + "=" + &v).collect();
    let canonical_query = query_strings.connect("&");

    // ----

    let canonical_request = format!("{}\n{}\n{}\n{}\n{}\n{}", method, fixed_uri, canonical_query, canonical_headers, signed_headers, content_hash);

    // println!("Canonical Request:\n{}", canonical_request);

    let scope = format!("{}/{}/{}/aws4_request", request_date, region_str(region), "s3");
    let request_hash = sha256(canonical_request.as_bytes());
    let str_to_sign = format!("AWS4-HMAC-SHA256\n{}\n{}\n{}", &request_time, scope, request_hash);

    // println!("String To Sign:\n{}", str_to_sign);

    // ----

    let sig : String = hmac_sha256( &aws_signing_key(region, "s3", request_date), str_to_sign.as_bytes() ).to_hex();

    // println!("Signature:\n{}", sig);

    // ----

    let auth = format!("AWS4-HMAC-SHA256 Credential={}/{}/{}/s3/aws4_request,SignedHeaders={},Signature={}",
                       aws_access_key_id(), request_date, region_str(region), signed_headers, sig);

    // println!("Auth:\n{}", auth);

    let response = request.header("Authorization", &auth).exec().unwrap();

    //println!("code={:?}; headers={:?}; body={}",
    //           response.get_code(), response.get_headers(), from_utf8(response.get_body()).unwrap());

    match response.get_code() {
        200 => Ok(response),
        _   => Err(io::Error::new(io::ErrorKind::Other, format!("Received error response from S3: {}", response)))
    }
}

fn parse_xml_response (xml_str : &[u8], xpath : &str) -> Result<String, String> {
    let path = Path::new(xpath);
    let mut cur_path = PathBuf::from("/");

    let reader = io::Cursor::new(xml_str);
    let mut parser = xml::reader::EventReader::new(reader);
    for e in parser.events() {
        match e {
            xml::reader::events::XmlEvent::StartElement { name, attributes: _, namespace: _ } => {
                cur_path.push(name.to_repr());
            },
            xml::reader::events::XmlEvent::EndElement { name: _ } => {
                if cur_path.as_path() == path {
                    return Ok(String::new())
                }
                cur_path.pop();
            },
            xml::reader::events::XmlEvent::Characters(s) => {
                if cur_path.as_path() == path {
                    return Ok(s)
                }
            },
            xml::reader::events::XmlEvent::Error(e) => {
                return Err(format!("Received XmlEvent::Error - {:?}", e));
            }
            _ => { }
        }
    }
    Err(format!("Element {} was not found", xpath))
}

fn aws_s3_bucket_location (bucket : &String) -> io::Result<AwsRegion> {
    let resp = try!(aws_s3_request(&HttpMethod::Get, AwsRegion::UsEast1, "s3.amazonaws.com", &format!("/{}", bucket), "location", &[]));
    let body = resp.get_body();
    match parse_xml_response(body, "/LocationConstraint") {
        Ok(s)  => Ok(str_to_region(&s)),
        Err(_) => Err(io::Error::new(io::ErrorKind::Other, "Error parsing xml response from S3"))
    }
}

pub fn head (bucket : &String, path : &String) -> io::Result<HashMap<String, Vec<String>>> {
    let region   = try!(aws_s3_bucket_location(bucket));
    let endpoint = format!("{}.{}", bucket, s3_endpoint(region));
    let resp     = try!(aws_s3_request(&HttpMethod::Head, region, &endpoint, path, "", &[]));
    Ok(resp.get_headers().clone())
}

pub fn get (bucket : &String, path : &String) -> io::Result<Vec<u8>> {
    let region   = try!(aws_s3_bucket_location(bucket));
    let endpoint = format!("{}.{}", bucket, s3_endpoint(region));
    let resp     = try!(aws_s3_request(&HttpMethod::Get, region, &endpoint, path, "", &[]));
    Ok(resp.move_body())
}

pub fn put (bucket : &String, path : &String, file : &Path, headers : &[(&str, &str)]) -> io::Result<()> {
    let region   = try!(aws_s3_bucket_location(bucket));
    let endpoint = format!("{}.{}", bucket, s3_endpoint(region));
    try!(aws_s3_request(&HttpMethod::Put(file.to_path_buf()), region, &endpoint, path, "", headers));
    Ok(())
}

// ---------------------------------------------------------------------------------------------------------------------

enum HttpMethod {
    Head,
    Get,
    Put(PathBuf)
}

impl fmt::Display for HttpMethod {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            HttpMethod::Head   => f.write_str("HEAD"),
            HttpMethod::Get    => f.write_str("GET"),
            HttpMethod::Put(_) => f.write_str("PUT")
        }
    }
}


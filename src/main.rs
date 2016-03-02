extern crate hyper;
extern crate openssl;
extern crate rustc_serialize;
extern crate docopt;

////////////////////////////////////////////////////////////////////////////////////////
////////////////////
//////////////////// SSL Client for Rust
////////////////////
////////////////////////////////////////////////////////////////////////////////////////

use hyper::Client;
use hyper::header::{Connection,ContentType};

use std::path::Path;
use openssl::ssl::{SslContext,SslMethod};
use openssl::ssl::error::SslError;
use openssl::x509::X509FileType;
use std::sync::Arc;
use hyper::net::Openssl;
pub fn ssl_context<C>(cacert: C, cert: C, key: C) -> Result<Openssl, SslError>
    where C: AsRef<Path> {
    let mut ctx = SslContext::new(SslMethod::Sslv23).unwrap();
    try!(ctx.set_cipher_list("DEFAULT"));
    try!(ctx.set_CA_file(cacert.as_ref()));
    try!(ctx.set_certificate_file(cert.as_ref(), X509FileType::PEM));
    try!(ctx.set_private_key_file(key.as_ref(), X509FileType::PEM));
    Ok(Openssl { context: Arc::new(ctx) })
}

use hyper::net::HttpsConnector;
pub fn ssl_connector<C>(cacert: C, cert: C, key: C) -> HttpsConnector<Openssl>
    where C: AsRef<Path> {
    let ctx = ssl_context(cacert, cert, key).ok().expect("error opening certificate files");
    HttpsConnector::new(ctx)
}

#[derive(Default)]
pub struct Config {
    pub server_urls: Vec<String>,
    pub cacert: String,
    pub cert: String,
    pub key: String,
}

pub fn client(config: Config) -> Client {
    if !config.cacert.is_empty() {
        let conn = ssl_connector(Path::new(&config.cacert),
                                 Path::new(&config.cert),
                                 Path::new(&config.key));
        Client::with_connector(conn)
    } else {
        Client::new()
    }
}

////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////
////////////////////
//////////////////// JSON Streaming from an io::Read to an io::Write
////////////////////
////////////////////////////////////////////////////////////////////////////////////////

use std::io::{self,Read,Write};
use std::mem::swap;
use rustc_serialize::json as json;

pub struct Streamer<T> {
    parser: json::Parser<T>,
    token: Option<json::JsonEvent>,
    indent: u32,
}

fn spaces(wr: &mut io::Write, n: u32) -> io::Result<()> {
    let mut n = n as usize;
    const BUF: &'static [u8] = b"                ";

    while n >= BUF.len() {
        try!(wr.write(BUF));
        n -= BUF.len();
    }

    if n > 0 {
        try!(wr.write(&BUF[..n]));
    }
    Ok(())
}

pub fn escape_bytes(wr: &mut io::Write, bytes: &[u8]) -> io::Result<()> {
    try!(wr.write_all(b"\""));

    let mut start = 0;

    for (i, byte) in bytes.iter().enumerate() {
        let escaped = match *byte {
            b'"' => b"\\\"",
            b'\\' => b"\\\\",
            b'\x08' => b"\\b",
            b'\x0c' => b"\\f",
            b'\n' => b"\\n",
            b'\r' => b"\\r",
            b'\t' => b"\\t",
            _ => { continue; }
        };

        if start < i {
            try!(wr.write_all(&bytes[start..i]));
        }

        try!(wr.write_all(escaped));

        start = i + 1;
    }

    if start != bytes.len() {
        try!(wr.write_all(&bytes[start..]));
    }

    try!(wr.write_all(b"\""));
    Ok(())
}

pub fn escape_str(wr: &mut io::Write, value: &str) -> io::Result<()> {
    escape_bytes(wr, value.as_bytes())
}

impl<T: Iterator<Item = char>> Streamer<T> {
    pub fn new(src: json::Parser<T>) -> Streamer<T> {
        Streamer { parser: src,
                   token: None,
                   indent: 2,
        }
    }

    pub fn stream(&mut self, dest: &mut io::Write) -> Result<(), json::BuilderError> {
        self.bump();
        let result = self.build_value(dest, 0);
        self.bump();
        match self.token.take() {
            None => {}
            Some(json::JsonEvent::Error(e)) => { return Err(e); }
            _ => {
                return Err(
                    json::ParserError::SyntaxError(
                        json::ErrorCode::InvalidSyntax, 0, 0)); }
        }
        result
    }

    fn bump(&mut self) {
        self.token = self.parser.next();
    }

    fn build_value(&mut self, dest: &mut io::Write, curr_indent: u32)
                   -> Result<(), json::BuilderError>
    {
        return match self.token.take() {
            Some(json::JsonEvent::NullValue) => {try!(write!(dest, "null")); Ok(())},
            Some(json::JsonEvent::I64Value(n)) => {try!(write!(dest, "{}", n)); Ok(())},
            Some(json::JsonEvent::U64Value(n)) => {try!(write!(dest, "{}", n)); Ok(())},
            Some(json::JsonEvent::F64Value(n)) => {try!(write!(dest, "{}", n)); Ok(())},
            Some(json::JsonEvent::BooleanValue(b)) => {
                if b { try!(write!(dest, "true")) }
                else { try!(write!(dest, "false"))};
                Ok(())},
            Some(json::JsonEvent::StringValue(ref mut s)) => {
                let mut temp = String::new();
                swap(s, &mut temp);
                try!(escape_str(dest, &temp));
                Ok(())
            }
            Some(json::JsonEvent::ArrayStart) => self.build_array(dest, curr_indent),
            Some(json::JsonEvent::ObjectStart) => self.build_object(dest, curr_indent),
            Some(json::JsonEvent::Error(e)) => Err(e),
            Some(json::JsonEvent::ObjectEnd) =>
                Err(json::ParserError::SyntaxError(
                    json::ErrorCode::InvalidSyntax, 0, 0)),
            Some(json::JsonEvent::ArrayEnd) =>
                Err(json::ParserError::SyntaxError(
                    json::ErrorCode::InvalidSyntax, 0, 0)),
            None =>
                Err(json::ParserError::SyntaxError(
                    json::ErrorCode::EOFWhileParsingValue, 0, 0)),
        }
    }

    fn build_array(&mut self, dest: &mut io::Write, old_indent: u32)
                   -> Result<(), json::BuilderError>
    {
        let mut idx = 0;
        let mut curr_indent = old_indent;
        self.bump();
        if let Some(json::JsonEvent::ArrayEnd) = self.token {
            try!(write!(dest, "[]"));
            return Ok(());
        } else {
            try!(write!(dest, "["));
            curr_indent += self.indent;
            loop {
                if idx != 0 {
                    try!(write!(dest, ","));
                }
                try!(write!(dest, "\n"));
                try!(spaces(dest, curr_indent));
                if let Err(e) = self.build_value(dest, curr_indent) {
                    return Err(e);
                };

                self.bump();
                idx += 1;

                if let Some(json::JsonEvent::ArrayEnd) = self.token {
                    curr_indent -= self.indent;
                    try!(write!(dest, "\n"));
                    try!(spaces(dest, curr_indent));
                    try!(write!(dest, "]"));
                    return Ok(());
                }

                if None == self.token {
                    return Err(
                        json::ParserError::SyntaxError(
                            json::ErrorCode::EOFWhileParsingArray, 0, 0));
                }
            }

        }
    }

    fn build_object(&mut self, dest: &mut io::Write, old_indent: u32)
                    -> Result<(), json::BuilderError>
    {
        let mut idx = 0;
        let mut curr_indent = old_indent;
        self.bump();
        match self.token.take() {
            Some(json::JsonEvent::ObjectEnd) => {
                try!(write!(dest, "{{}}"));
                return Ok(());
            }
            Some(json::JsonEvent::Error(e)) => { return Err(e); }
            None => {
                return Err(
                    json::ParserError::SyntaxError(
                        json::ErrorCode::EOFWhileParsingObject, 0, 0)); }
            token => { self.token = token; }
        }

        try!(write!(dest, "{{"));
        curr_indent += self.indent;
        loop {
            if idx != 0 {
                try!(write!(dest, ","));
            }
            try!(write!(dest, "\n"));
            try!(spaces(dest, curr_indent));
            // The token's we get from the stack don't include Object keys, we
            // have to get those directly from the stack
            let key = match self.parser.stack().top() {
                Some(json::StackElement::Key(k)) => { k.to_string() }
                _ => { panic!("invalid state"); }
            };
            try!(write!(dest, "{:?}: ",key));
            if let Err(e) = self.build_value(dest, curr_indent) {
                return Err(e);
            };
            self.bump();
            idx += 1;

            match self.token.take() {
                Some(json::JsonEvent::ObjectEnd) => {
                    curr_indent -= self.indent;
                    try!(write!(dest, "\n"));
                    try!(spaces(dest, curr_indent));
                    try!(write!(dest, "}}"));
                    return Ok(());
                }
                Some(json::JsonEvent::Error(e)) => { return Err(e); }
                None => {
                    return Err(
                        json::ParserError::SyntaxError(
                            json::ErrorCode::EOFWhileParsingObject, 0, 0)); }
                token => { self.token = token; }
            }
        }
    }
}

////////////////////////////////////////////////////////////////////////////////////////

////////////////////////////////////////////////////////////////////////////////////////
////////////////////
//////////////////// Argument parsing for Rust
////////////////////
////////////////////////////////////////////////////////////////////////////////////////

use docopt::Docopt;

const USAGE: &'static str = "
Pretty Print JSON.

Usage:
  pretty-print (--version | --help)
  pretty-print <url> [--body=<fields>]

Options:
  -h --help        Show this screen.
  -v --version     Show version.
  --body=<fields>  String body to use in POST request [default: none].
";

const VERSION: Option<&'static str> = option_env!("CARGO_PKG_VERSION");
#[derive(Debug, RustcDecodable)]
struct Args {
    flag_version: bool,
    arg_url: Option<String>,
    flag_body: Option<String>,
}

fn main() {
    let args: Args = Docopt::new(USAGE)
                            .and_then(|d| d.decode())
                            .unwrap_or_else(|e| e.exit());
    if args.flag_version {
        println!("Pretty Print JSON v{}", VERSION.unwrap_or("unknown"));
        return;
    }

    let url = args.arg_url.unwrap();
    let body = args.flag_body.unwrap_or("".to_string());
    // Add your SSL credentials here if you'd like
    let mut response = Client::new()
        .post(&url)
        .body(&body)
        .header(ContentType::json())
        .header(Connection::close())
        .send()
        .unwrap();

    let status = response.status;
    if status != hyper::Ok {
        let mut temp = String::new();
        match response.read_to_string(&mut temp) {
            Ok(_) => {},
            Err(x) => panic!("Unable to read response from server: {}", x),
        };
        match writeln!(&mut std::io::stderr(), "Error response from server: {}", temp) {
            Ok(_) => {},
            Err(x) => panic!("Unable to write to stderr: {}", x),
        };
        std::process::exit(1)
    }

    let parser = json::Parser::new(response
                                   .bytes()
                                   .map(|c| c.unwrap() as char));

    let mut streamer = Streamer::new(parser);

    let stdout = io::stdout();
    let mut handle = stdout.lock();
    if let Err(e) = streamer.stream(&mut handle) {
        match writeln!(&mut std::io::stderr(), "Error parsing output: {}", e) {
            Ok(_) => {},
            Err(x) => panic!("Unable to write to stderr: {}", x),
        };
        std::process::exit(1)
    };
}

////////////////////////////////////////////////////////////////////////////////////////

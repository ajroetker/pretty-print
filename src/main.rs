extern crate hyper;
extern crate openssl;
extern crate rustc_serialize;
extern crate docopt;
extern crate prettifier;

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

use std::io::{self,Read,Write};
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

    let stdout = io::stdout();
    if let Err(e) = prettifier::prettify(&mut response, &mut stdout.lock()) {
        match writeln!(&mut std::io::stderr(), "Error parsing output: {}", e) {
            Ok(_) => {},
            Err(x) => panic!("Unable to write to stderr: {}", x),
        };
        std::process::exit(1)
    };
}

////////////////////////////////////////////////////////////////////////////////////////

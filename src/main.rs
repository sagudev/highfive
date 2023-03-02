use std::path::PathBuf;

use clap::Parser;
use octocrab::models::events::payload;
use once_cell::sync::OnceCell;
use rocket::form::{Form, Strict};
use rocket::{
    get,
    http::Status,
    post,
    request::{self, FromRequest},
    routes, FromForm, Responder,
};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Cli {
    /// Port for web server
    #[clap(long, value_parser, default_value_t = 8000, env = "HIGHFIVE_PORT")]
    port: u16,

    /// GitHub Token
    #[clap(long, env = "HIGHFIVE_GITHUB_TOKEN")]
    github_token: String,

    /// Webhook secret
    #[clap(long = "webhook-secret", env = "HIGHFIVE_WEBHOOK_SECRET")]
    webhook_secrets: Vec<String>,

    /// Config directory
    #[clap(long, env = "HIGHFIVE_CONFIG_DIR")]
    config_dir: Option<PathBuf>,
}

#[get("/")]
fn index() -> &'static str {
    "Welcome to highfive!\n"
}

struct Headers<'a> {
    event: Option<&'a str>,
    delivery: Option<&'a str>,
    signature: Option<&'a str>,
}

impl<'a> Headers<'a> {
    const fn is_valid(&self) -> bool {
        self.event.is_some() && self.delivery.is_some() && self.signature.is_some()
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Headers<'r> {
    type Error = ();

    async fn from_request(request: &'r rocket::Request<'_>) -> request::Outcome<Self, ()> {
        //let db = rocket::outcome::try_outcome!(request.guard::<Database>().await);
        let headers = request.headers();
        request::Outcome::Success(Headers {
            event: headers.get_one("X-GitHub-Event"),
            delivery: headers.get_one("X-GitHub-Delivery"),
            signature: headers.get_one("X-Hub-Signature"),
        })
    }
}

#[derive(Responder)]
enum Error {
    /// 500
    #[response(status = 500)]
    Internal(&'static str),
    /// 403
    #[response(status = 403)]
    Forbidden(&'static str),
    /// 400
    #[response(status = 400)]
    BadRequest(&'static str),
}

#[derive(FromForm)]
struct Payload<'r> {
    payload: &'r str,
}

#[post("/webhook", data = "<payload>")]
fn webhook(headers: Headers, payload: Option<Form<Payload>>) -> Result<&'static str, Error> {
    new_pr(headers, payload)
}

#[post("/newpr.py", data = "<payload>")]
fn newpr(headers: Headers, payload: Option<Form<Payload>>) -> Result<&'static str, Error> {
    new_pr(headers, payload)
}

#[post("/highfive/newpr.py", data = "<payload>")]
fn highfive(headers: Headers, payload: Option<Form<Payload>>) -> Result<&'static str, Error> {
    new_pr(headers, payload)
}

fn new_pr(headers: Headers, payload: Option<Form<Payload>>) -> Result<&'static str, Error> {
    if !headers.is_valid() {
        return Err(Error::Internal(
            "Error: some required webhook headers are missing\n",
        ));
    }
    if let Some(p) = payload {
        for webhook_secret in CLI.get().unwrap().webhook_secrets.iter() {
            let mut mac = Hmac::new_from_slice(webhook_secret.as_bytes()).unwrap();
            mac.update(p.payload.as_bytes());
            if mac
                .verify_slice(
                    &hex::decode(headers.signature.unwrap().replace("sha1=", "")).unwrap(),
                )
                .is_err()
            {
                return Err(Error::Forbidden("Error: invalid signature\n"));
            }
        }
    } else {
        return Err(Error::BadRequest("Error: missing payload\n"));
    }
    Ok("lol")
}

//use hex_literal::hex;
use hmac::Mac;

// Create alias for HMAC-SHA256
type Hmac = hmac::Hmac<sha2::Sha256>;

static CLI: OnceCell<Cli> = OnceCell::new();

fn main() {
    if dotenvy::dotenv().is_err() {
        println!("Failed with loading .env file");
    }

    CLI.set(Cli::parse()).unwrap();
    let cli = CLI.get().unwrap();

    // login into github and use this information for some aditional post processing on config
    let octocrab = match octocrab::Octocrab::builder()
        .personal_token(cli.github_token.to_owned())
        .build()
    {
        Ok(o) => o,
        Err(e) => {
            println!("error: invalid github token provided!");
            std::process::exit(1);
        }
    };

    rocket::tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            let user = octocrab.current().user().await?;
            let config = rocket::Config {
                port: cli.port,
                ..Default::default()
            };
            let _rocket = rocket::custom(config)
                .mount("/", routes![index])
                .launch()
                .await?;
            Ok::<_, Box<dyn std::error::Error>>(())
        })
        .unwrap();
}

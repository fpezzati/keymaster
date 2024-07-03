use serde_json::Value;
use serde_json::json;
//use cookie::Cookie;
use serde::{Deserialize, Serialize};
//use http::header::HeaderName;
//use jwt_simple::claims::Claims;
//use jwt_simple::prelude::{Duration, RS384KeyPair};

use axum::response::IntoResponse;
use axum::http::StatusCode;
use axum::http::header;
use axum::Json;
//use tokio::net::TcpListener;
//use std::net::SocketAddr;
use tokio::net::TcpStream;
use cookie::Cookie;
use jwt_simple::claims::Claims;
use jwt_simple::prelude::Duration;
use jwt_simple::prelude::RS384KeyPair;
use jwt_simple::algorithms::RSAKeyPairLike;

#[derive(Clone, Serialize, Deserialize)]
pub struct OAuth2Conf {
    client_id: String,
    redirect_uri: String,
    client_secret: String,
    idp_url: String,
}

impl OAuth2Conf {
    pub fn new(conf: Value) -> OAuth2Conf {
        OAuth2Conf {
            client_id: conf["client_id"].as_str().unwrap().to_string(),
            redirect_uri: conf["redirect_uri"].as_str().unwrap().to_string(),
            client_secret: conf["client_secret"].as_str().unwrap().to_string(),
            idp_url: conf["idp_url"].as_str().unwrap().to_string()
        }
    }
}

pub async fn request_token(oauth2_conf: Value, code: String) -> impl IntoResponse {
    let conf = OAuth2Conf::new(oauth2_conf);
    let token_url = format!(
        "{}?client_id={}&redirect_uri={}&client_secret={}&code={}",
        conf.idp_url, conf.client_id, conf.redirect_uri, conf.client_secret, code
    );

    let client = reqwest::Client::new();
    match client.get(token_url.as_str()).send().await {
        Ok(resp) => {
            if resp.status() == 200 {
                match resp.json::<Value>().await {
                    Ok(json_body) => {
                        
                    },
                    Err(e) => {
                        // no token, raise error
                    }
                }
            } else if resp.status() == 301 {
                let redirect_uri : String = resp.headers().get("Location").unwrap().to_str().unwrap().to_string();
                match client.post(redirect_uri.as_str()).header("Accept", "application/json").send().await {
                    Ok(redirect_resp) => {

                    },
                    Err(e) => {
                        // redirect went wrong, raise error
                    }
                }
            } else {
                // get token went wrong, raise error
            }
        },
        Err(err) => {

        }
    }
    (StatusCode::OK, ())
}

#[derive(Serialize, Deserialize)]
struct UserClaims {
    user: String,
    auth_provider: String,
    token: String
}

fn pick_token_and_provides_response(body_as_json: Value, private_key: String) -> impl IntoResponse {
    let token = body_as_json["access_token"].as_str().unwrap();
    let cookie = Cookie::build(("hey", token)).secure(true).http_only(true).build();
    let cookie_value = String::from(cookie.value());
    let pkey = RS384KeyPair::from_pem(private_key.as_str()).unwrap();

    let unsigned_claims = Claims::with_custom_claims(UserClaims {
      user: String::from("jimmy"),
      auth_provider: String::from("github"),
      token: token.to_string()
    }, Duration::from_hours(1));
    let signed_claims = pkey.sign(unsigned_claims).unwrap();

    #[derive(Deserialize)]
    struct Payload<'a> {
        msg: &'a str
    };

    return (
      StatusCode::OK,
      [(header::SET_COOKIE, signed_claims), (header::CONTENT_TYPE, "application/json".to_string())],
      Json(json!({
        "msg": "got the cookie"
      }))
    );
}
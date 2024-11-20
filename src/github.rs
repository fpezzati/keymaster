use core::fmt;

use axum::http::header;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::response::Response;
use axum::Json;
use cookie::Cookie;
use jwt_simple::algorithms::RSAKeyPairLike;
use jwt_simple::claims::Claims;
use jwt_simple::prelude::Duration;
use jwt_simple::prelude::RS384KeyPair;
use log::info;
use log::{debug, error};
use reqwest::header::ACCEPT;
use serde::{Deserialize, Serialize};
use serde_json::json;
use serde_json::Value;

#[derive(Clone, Serialize, Deserialize)]
pub struct OAuth2Conf {
    client_id: String,
    redirect_uri: String,
    client_secret: String,
    idp_url: String,
    get_user_email_url: String,
}

impl OAuth2Conf {
    fn new(conf: Value) -> Result<OAuth2Conf, GithubErr> {
        Ok(OAuth2Conf {
            client_id: conf["client_id"]
                .as_str()
                .ok_or(GithubErr {
                    message: "missing 'client_id' value in configuration".to_string(),
                    http_code: 500,
                })?
                .to_string(),
            redirect_uri: conf["redirect_uri"]
                .as_str()
                .ok_or(GithubErr {
                    message: "missing 'redirect_uri' value in configuration".to_string(),
                    http_code: 500,
                })?
                .to_string(),
            client_secret: conf["client_secret"]
                .as_str()
                .ok_or(GithubErr {
                    message: "missing 'client_secret' value in configuration".to_string(),
                    http_code: 500,
                })?
                .to_string(),
            idp_url: conf["idp_url"]
                .as_str()
                .ok_or(GithubErr {
                    message: "missing 'idp_url' value in configuration".to_string(),
                    http_code: 500,
                })?
                .to_string(),
            get_user_email_url: conf["get_user_email_url"]
                .as_str()
                .ok_or(GithubErr {
                    message: "missing 'get_user_email_url' value in configuration".to_string(),
                    http_code: 500,
                })?
                .to_string(),
        })
    }
}

pub async fn request_token(
    oauth2_conf: Value,
    code: String,
    application_name: String,
    private_key: String,
    domain: String,
) -> Response {
    let conf = OAuth2Conf::new(oauth2_conf)
        .map_err(|err| {
            return build_error_response(err);
        })
        .unwrap();
    let token_url = format!(
        "{}?client_id={}&client_secret={}&code={}&redirect_uri={}",
        conf.idp_url, conf.client_id, conf.client_secret, code, conf.redirect_uri
    );
    debug!("Ready to fetch token: {token_url}");
    let client = reqwest::Client::new();
    debug!("preparing token request");
    match client
        .get(token_url.as_str())
        .header(ACCEPT, "application/json")
        .send()
        .await
    {
        Ok(resp) => {
            let resp_status = resp.status();
            debug!("response: {resp_status}");
            if resp.status() == 200 {
                match handle_200(conf, application_name, private_key, domain, resp).await {
                    Ok(resp_to_200) => return resp_to_200,
                    Err(e) => {
                        return build_error_response(e);
                    }
                }
            } else if resp.status() == 301 {
                match handle_301(conf, application_name, private_key, domain, resp).await {
                    Ok(resp_to_301) => {
                        return resp_to_301;
                    }
                    Err(e) => {
                        return build_error_response(e);
                    }
                }
            } else {
                // get token went wrong, raise error
                let resp_body = resp.text().await.unwrap();
                error!("Getting token went wrong, Idp provider replies with an error: {resp_body}");
                return build_error_response(GithubErr {
                    message: format!("Error while fetching token. Original error: {}", resp_body)
                        .to_string(),
                    http_code: 500,
                });
            }
        }
        Err(err) => {
            error!("Token request went wrong.");
            return build_error_response(GithubErr {
                message: format!("Error while fetching token. Original error: {}", err).to_string(),
                http_code: 500,
            });
        }
    }
}

async fn handle_200(
    conf: OAuth2Conf,
    application_name: String,
    private_key: String,
    domain: String,
    resp: reqwest::Response,
) -> Result<Response, GithubErr> {
    match resp.text().await {
        Ok(text_body) => {
            debug!("Got response that should contains token in body: {text_body}");
            let json_body =
                serde_json::from_str::<serde_json::Value>(text_body.as_str()).map_err(|err| {
                    GithubErr {
                        message: err.to_string(),
                        http_code: 500,
                    }
                })?;
            let token = json_body["access_token"].as_str().ok_or(GithubErr {
                http_code: 500,
                message: String::from("Cannot find access_token element in response body."),
            })?;
            let user_email_to_send =
                get_user_email(String::from(token), conf.get_user_email_url).await?;
            let cookie_to_send = build_cookie(
                String::from(token),
                application_name,
                user_email_to_send.clone(),
                private_key,
                domain,
            )?;
            Ok(build_succesful_response(cookie_to_send, user_email_to_send))
        }
        Err(e) => {
            error!("Something wrong while reading response. Original error: {e}");
            Err(GithubErr {
                http_code: 500,
                message: format!(
                    "Something wrong while reading response. Original error: {}",
                    e
                )
                .to_string(),
            })
        }
    }
}

async fn handle_301(
    conf: OAuth2Conf,
    application_name: String,
    private_key: String,
    domain: String,
    resp: reqwest::Response,
) -> Result<Response, GithubErr> {
    debug!("Redirect detected.");
    let redirect_uri = resp
        .headers()
        .get("Location")
        .ok_or(GithubErr {
            http_code: 500,
            message: String::from("No 'Location' found in redirect response."),
        })?
        .to_str()
        .map_err(|err| GithubErr {
            message: err.to_string(),
            http_code: 500,
        })?;
    let client = reqwest::Client::new();
    let redirect_resp = client
        .post(String::from(redirect_uri))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|err| GithubErr {
            message: err.to_string(),
            http_code: 500,
        })?;
    debug!("Redirect went fine.");
    let redirect_body = redirect_resp
        .json::<Value>()
        .await
        .map_err(|err| GithubErr {
            message: err.to_string(),
            http_code: 500,
        })?;
    debug!("Getting token from redirect.");
    let token = redirect_body["access_token"].as_str().ok_or(GithubErr {
        http_code: 500,
        message: String::from("Cannot find access_token element in response body."),
    })?;
    let user_email_to_send = get_user_email(String::from(token), conf.get_user_email_url).await?;
    let cookie_to_send = build_cookie(
        String::from(token),
        application_name,
        user_email_to_send.clone(),
        private_key,
        domain,
    )?;
    let successful_resp: Response = build_succesful_response(cookie_to_send, user_email_to_send);
    Ok(successful_resp)
}

#[derive(Serialize, Deserialize)]
struct UserClaims {
    user: String,
    auth_provider: String,
    token: String,
}

#[derive(Debug)]
struct GithubErr {
    message: String,
    http_code: u16,
}

impl fmt::Display for GithubErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "meh...")
    }
}

impl std::error::Error for GithubErr {}

fn build_cookie(
    token: String,
    application_name: String,
    user: String,
    private_key: String,
    domain: String,
) -> Result<String, GithubErr> {
    let pkey = RS384KeyPair::from_pem(private_key.as_str()).unwrap();
    let unsigned_claims = Claims::with_custom_claims(
        UserClaims {
            user: user,
            auth_provider: String::from("github"),
            token: token,
        },
        Duration::from_hours(1),
    );
    let signed_claims = pkey.sign(unsigned_claims).map_err(|error| GithubErr {
        http_code: 500,
        message: format!("error while signing claims. Original error was: {}", error),
    })?;
    info!("building cookie: {}, {}", application_name, signed_claims);
    //let cookie = Cookie::build((
    //    application_name.as_str(),
    //    format!("{}={}", application_name, signed_claims).to_string(),
    //))
    //.domain(domain)
    //.path("/")
    //.secure(true)
    //.http_only(true)
    //.max_age(cookie::time::Duration::days(1))
    //.build();
    let cookie_as_string = format!(
        "{}={}; Domain={}; Path=/; Secure; HttpOnly; Max-Age={}",
        application_name, signed_claims, domain, 86400
    );
    return Ok(cookie_as_string);
}

async fn get_user_email(token: String, get_user_email_url: String) -> Result<String, GithubErr> {
    #[derive(Serialize, Deserialize)]
    struct GithubUserEmail {
        email: String,
        primary: bool,
        verified: bool,
        visibility: String,
    }
    info!("Fetching user email: {get_user_email_url}");
    let client = reqwest::Client::new();
    let request = client
        .get(get_user_email_url.as_str())
        .header("Accept", "application/vnd.github+json")
        .header("Authorization", format!("Bearer {}", token).as_str())
        .header("X-GitHub-Api-Version", "2022-11-28")
        .header("User-Agent", "Mozilla/5.0")
        .build()
        .unwrap();
    info!("sending request for fetching user's email: {:?}", request);
    match client.execute(request).await {
        Ok(resp) => match resp.status() {
            StatusCode::OK => match resp.text().await {
                Ok(text_body) => {
                    debug!("Got response that should contains token in body: {text_body}");
                    let github_payload: Vec<GithubUserEmail> =
                        serde_json::from_str(text_body.as_str()).unwrap();
                    let username: String = github_payload[0].email.clone();
                    Ok(username)
                }
                Err(e) => Err(GithubErr {
                    message: format!("cannot read server's reply. Error: {}", e),
                    http_code: 500,
                }),
            },
            _ => {
                error!(
                    "Got error while fetching user email. http response: {:?}",
                    resp
                );
                Err(GithubErr {
                    message: String::from("error while fetching user email."),
                    http_code: resp.status().as_u16(),
                })
            }
        },
        Err(error) => Err(GithubErr {
            message: format!("error while reading reply: {}", error),
            http_code: 500,
        }),
    }
}

fn build_succesful_response(cookie_value: String, user_email: String) -> Response {
    info!(
        "building response with user_email: {}, cookie: {}",
        user_email, cookie_value
    );
    return (
        StatusCode::OK,
        [
            (header::SET_COOKIE, cookie_value),
            (header::CONTENT_TYPE, "application/json".to_string()),
        ],
        Json(json!({
          "user_email": user_email
        })),
    )
        .into_response();
}

fn build_error_response(error: GithubErr) -> Response {
    #[derive(Serialize, Deserialize)]
    struct ErrorResponsePayload {
        error: String,
    }

    let error_msg_as_json = ErrorResponsePayload {
        error: error.message,
    };
    return (
        StatusCode::from_u16(error.http_code).unwrap(),
        [(header::CONTENT_TYPE, "application/json".to_string())],
        Json(serde_json::to_value(error_msg_as_json).unwrap()),
    )
        .into_response();
}

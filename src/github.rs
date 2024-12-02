use axum::http::StatusCode;
use log::{debug, error, info};
use reqwest::header::ACCEPT;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::server::ServerError;
use crate::server::UserClaims;

#[derive(Clone, Serialize, Deserialize)]
pub struct OAuth2Conf {
    client_id: String,
    redirect_uri: String,
    client_secret: String,
    idp_url: String,
    get_user_email_url: String,
}

impl OAuth2Conf {
    fn new(conf: Value) -> Result<OAuth2Conf, ServerError> {
        Ok(OAuth2Conf {
            client_id: conf["client_id"]
                .as_str()
                .ok_or(ServerError {
                    message: "missing 'client_id' value in configuration".to_string(),
                    http_code: 500,
                })?
                .to_string(),
            redirect_uri: conf["redirect_uri"]
                .as_str()
                .ok_or(ServerError {
                    message: "missing 'redirect_uri' value in configuration".to_string(),
                    http_code: 500,
                })?
                .to_string(),
            client_secret: conf["client_secret"]
                .as_str()
                .ok_or(ServerError {
                    message: "missing 'client_secret' value in configuration".to_string(),
                    http_code: 500,
                })?
                .to_string(),
            idp_url: conf["idp_url"]
                .as_str()
                .ok_or(ServerError {
                    message: "missing 'idp_url' value in configuration".to_string(),
                    http_code: 500,
                })?
                .to_string(),
            get_user_email_url: conf["get_user_email_url"]
                .as_str()
                .ok_or(ServerError {
                    message: "missing 'get_user_email_url' value in configuration".to_string(),
                    http_code: 500,
                })?
                .to_string(),
        })
    }
}

pub async fn request_token(oauth2_conf: Value, code: String) -> Result<UserClaims, ServerError> {
    let conf = OAuth2Conf::new(oauth2_conf)?;
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
                let token_to_send = handle_200(resp).await?;
                let user_email_to_send =
                    get_user_email(token_to_send.clone(), conf.get_user_email_url).await?;
                return Ok(UserClaims {
                    auth_provider: "TODO".to_string(),
                    token: token_to_send,
                    user: user_email_to_send,
                });
            } else if resp.status() == 301 {
                let token_to_send = handle_301(resp).await?;
                let user_email_to_send =
                    get_user_email(token_to_send.clone(), conf.get_user_email_url).await?;
                return Ok(UserClaims {
                    auth_provider: "TODO".to_string(),
                    token: token_to_send,
                    user: user_email_to_send,
                });
            } else {
                // get token went wrong, raise error
                let resp_body = resp.text().await.unwrap();
                error!("Getting token went wrong, Idp provider replies with an error: {resp_body}");
                Err(ServerError {
                    message: format!("Error while fetching token. Original error: {}", resp_body)
                        .to_string(),
                    http_code: 500,
                })
            }
        }
        Err(err) => {
            error!("Token request went wrong.");
            Err(ServerError {
                message: format!("Error while fetching token. Original error: {}", err).to_string(),
                http_code: 500,
            })
        }
    }
}

async fn handle_200(resp: reqwest::Response) -> Result<String, ServerError> {
    match resp.text().await {
        Ok(text_body) => {
            debug!("Got response that should contains token in body: {text_body}");
            let json_body =
                serde_json::from_str::<serde_json::Value>(text_body.as_str()).map_err(|err| {
                    ServerError {
                        message: err.to_string(),
                        http_code: 500,
                    }
                })?;
            let token = json_body["access_token"].as_str().ok_or(ServerError {
                http_code: 500,
                message: String::from("Cannot find access_token element in response body."),
            })?;
            Ok(token.to_string())
        }
        Err(e) => {
            error!("Something wrong while reading response. Original error: {e}");
            Err(ServerError {
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

async fn handle_301(resp: reqwest::Response) -> Result<String, ServerError> {
    debug!("Redirect detected.");
    let redirect_uri = resp
        .headers()
        .get("Location")
        .ok_or(ServerError {
            http_code: 500,
            message: String::from("No 'Location' found in redirect response."),
        })?
        .to_str()
        .map_err(|err| ServerError {
            message: err.to_string(),
            http_code: 500,
        })?;
    let client = reqwest::Client::new();
    let redirect_resp = client
        .post(String::from(redirect_uri))
        .header("Accept", "application/json")
        .send()
        .await
        .map_err(|err| ServerError {
            message: err.to_string(),
            http_code: 500,
        })?;
    debug!("Redirect went fine.");
    let redirect_body = redirect_resp
        .json::<Value>()
        .await
        .map_err(|err| ServerError {
            message: err.to_string(),
            http_code: 500,
        })?;
    debug!("Getting token from redirect.");
    let token = redirect_body["access_token"].as_str().ok_or(ServerError {
        http_code: 500,
        message: String::from("Cannot find access_token element in response body."),
    })?;
    Ok(token.to_string())
}

async fn get_user_email(token: String, get_user_email_url: String) -> Result<String, ServerError> {
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
                Err(e) => Err(ServerError {
                    message: format!("cannot read server's reply. Error: {}", e),
                    http_code: 500,
                }),
            },
            _ => {
                error!(
                    "Got error while fetching user email. http response: {:?}",
                    resp
                );
                Err(ServerError {
                    message: String::from("error while fetching user email."),
                    http_code: resp.status().as_u16(),
                })
            }
        },
        Err(error) => Err(ServerError {
            message: format!("error while reading reply: {}", error),
            http_code: 500,
        }),
    }
}

use axum::{
    extract::{Path, Query, State},
    http::{
        header::{AUTHORIZATION, CONTENT_TYPE, COOKIE, SET_COOKIE},
        HeaderMap, StatusCode,
    },
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use core::fmt;
use log::{error, info};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::fs;
use std::net::SocketAddr;
use tokio::net::TcpListener;

use jwt_simple::algorithms::RSAKeyPairLike;
use jwt_simple::claims::Claims;
use jwt_simple::prelude::Duration;
use jwt_simple::prelude::RS384KeyPair;

use crate::github;
use crate::verify;

#[derive(Clone)]
pub struct ServerConfig {
    host: String,
    port: String,
    application_name: String,
    domain: String,
    public_key: String,
    private_key: String,
    pub oauth2_conf: String,
}

impl ServerConfig {
    pub async fn start(config: &str) {
        println!("{}", config);
        let json_content: Value = serde_json::from_str(&config).expect("Invalid file.");
        let public_key_content =
            fs::read_to_string(String::from(json_content["public_key"].as_str().unwrap())).unwrap();
        let private_key_content =
            fs::read_to_string(String::from(json_content["private_key"].as_str().unwrap()))
                .unwrap();
        let server = ServerConfig {
            host: String::from(
                json_content["host"]
                    .as_str()
                    .expect("invalid host specified"),
            ), //seems odd but using to_string causes quotes to pollute value.
            port: json_content["port"].to_string(),
            application_name: json_content["application_name"]
                .as_str()
                .unwrap()
                .to_string(),
            public_key: public_key_content,
            private_key: private_key_content,
            oauth2_conf: json_content["oauth2_conf"].to_string(),
            domain: json_content["domain"].as_str().unwrap().to_string(),
        };
        log4rs::init_file(
            json_content["log_conf"].as_str().unwrap(),
            Default::default(),
        )
        .unwrap();

        let mut hostport = String::new();
        hostport.push_str(server.host.as_str());
        hostport.push_str(":");
        hostport.push_str(server.port.as_str());
        println!("hostport: {}", hostport);
        let server_socket = hostport
            .parse::<SocketAddr>()
            .expect("invalid host:port pair");

        let routes = Router::new()
            .route("/", get(hello))
            .route("/verify", get(handle_verify).post(handle_verify))
            .route("/callback/:id_provider", get(callback))
            .with_state(server);
        let listener = TcpListener::bind(server_socket).await.unwrap();

        axum::serve(listener, routes).await.unwrap();
    }
}

async fn hello(State(server): State<ServerConfig>) -> impl IntoResponse {
    (StatusCode::OK, Json(String::from(&server.oauth2_conf)))
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct CallbackAuthParams {
    code: String,
}

pub async fn callback(
    State(server_config): State<ServerConfig>,
    Path(id_provider): Path<String>,
    Query(params): Query<CallbackAuthParams>,
) -> impl IntoResponse {
    info!("id_provider: {}", id_provider.as_str());
    let oauth2_config: Value =
        serde_json::from_str(server_config.oauth2_conf.as_str()).expect("Invalid configuration.");
    let oauth2_config_provider = oauth2_config[id_provider.as_str()].clone();
    match github::request_token(oauth2_config_provider, params.code).await {
        Ok(mut claims) => {
            info!(
                "Got token and user to send back: {}, {}",
                claims.token, claims.user
            );
            claims.auth_provider = id_provider;
            let cookie_value = build_cookie(
                claims.clone(),
                server_config.application_name,
                server_config.private_key,
                server_config.domain,
            )
            .unwrap();

            info!(
                "building response with user_email: {}, cookie: {}",
                claims.user, cookie_value
            );
            return (
                StatusCode::OK,
                [
                    (SET_COOKIE, cookie_value),
                    (CONTENT_TYPE, "application/json".to_string()),
                ],
                Json(json!({
                  "user_email": claims.user
                })),
            )
                .into_response();
        }
        Err(err) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(CONTENT_TYPE, "application/json".to_string())],
                Json(json!({
                    "error": err.to_string()
                })),
            )
                .into_response()
        }
    }
}

fn build_cookie(
    claims_to_sign: UserClaims,
    application_name: String,
    private_key: String,
    domain: String,
) -> Result<String, GithubErr> {
    let pkey = RS384KeyPair::from_pem(private_key.as_str()).unwrap();
    let unsigned_claims = Claims::with_custom_claims(claims_to_sign, Duration::from_hours(1));
    let signed_claims = pkey.sign(unsigned_claims).map_err(|error| GithubErr {
        http_code: 500,
        message: format!("error while signing claims. Original error was: {}", error),
    })?;
    info!("building cookie: {}, {}", application_name, signed_claims);
    let cookie_as_string = format!(
        "{}={}; Domain={}; Path=/; Secure; HttpOnly; Max-Age={}",
        application_name, signed_claims, domain, 86400
    );
    return Ok(cookie_as_string);
}

#[derive(Debug)]
pub enum ServerError {
    VerifyError,
    RequireTokenError,
}

#[derive(Debug)]
pub struct GithubErr {
    pub message: String,
    pub http_code: u16,
}

impl fmt::Display for GithubErr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "meh...")
    }
}

impl std::error::Error for GithubErr {}

#[derive(Serialize, Deserialize, Clone)]
pub struct UserClaims {
    pub user: String,
    pub auth_provider: String,
    pub token: String,
}

impl fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerError::VerifyError => write!(f, "VERIFY-ERROR"),
            ServerError::RequireTokenError => write!(f, "REQUIRE-TOKEN-ERROR"),
        }
    }
}

async fn handle_verify(
    State(server_config): State<ServerConfig>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let mut where_to_find_token_in_header = headers.get(AUTHORIZATION);
    if headers.get(COOKIE).is_some() {
        where_to_find_token_in_header = headers.get(COOKIE);
    }
    if where_to_find_token_in_header.is_none() {
        error!("Nor AUTHORIZATION header, nor COOKIE value found to verify.");
        return (StatusCode::BAD_REQUEST).into_response();
    }
    let token_found = where_to_find_token_in_header
        .unwrap()
        .to_str()
        .map_err(|err| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(CONTENT_TYPE, "application/json".to_string())],
                Json(serde_json::to_value(format!(
                    "Cannot parse token value. Original error: {}",
                    err
                ))),
            )
        })
        .unwrap();
    let token_to_check: String;
    if headers.get(AUTHORIZATION).is_some() {
        info!("AUTHORIZATION: {}", token_found);
        token_to_check = str::replace(token_found, "Bearer ", "");
    } else {
        info!("COOKIE: {}", token_found);
        token_to_check = token_found.to_string();
    }
    match verify::check_token(server_config.public_key, token_to_check).await {
        Ok(res) => {
            if res {
                (StatusCode::OK).into_response()
            } else {
                (StatusCode::UNAUTHORIZED).into_response()
            }
        }
        Err(err) => (
            StatusCode::UNAUTHORIZED,
            [(CONTENT_TYPE, "application/json".to_string())],
            Json(
                serde_json::to_value(format!(
                    "An error occurred while checking the token: {}",
                    err
                ))
                .unwrap(),
            ),
        )
            .into_response(),
    }
}

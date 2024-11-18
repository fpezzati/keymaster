use axum::{
    extract::{Path, Query, State},
    http::header::{AUTHORIZATION, CONTENT_TYPE, COOKIE},
    http::HeaderMap,
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use cookie::Cookie;
use log::{debug, error, info};
use serde_json::Value;
use std::fs;
use std::net::SocketAddr;
use tokio::net::TcpListener;

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
            application_name: json_content["application_name"].to_string(),
            public_key: public_key_content,
            private_key: private_key_content,
            oauth2_conf: json_content["oauth2_conf"].to_string(),
            domain: json_content["domain"].to_string(),
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
            .route("/verify", get(verify).post(verify))
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
    github::request_token(
        oauth2_config_provider,
        params.code,
        server_config.application_name,
        server_config.private_key,
        server_config.domain,
    )
    .await
}

async fn verify(
    State(server_config): State<ServerConfig>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if headers.get(COOKIE).is_some() {
        let authorization_header_value = headers
            .get(COOKIE)
            .unwrap()
            .to_str()
            .map_err(|err| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(CONTENT_TYPE, "application/json".to_string())],
                    Json(serde_json::to_value(format!(
                        "Cannot parse COOKIE value to string. Original error: {}",
                        err
                    ))),
                )
            })
            .unwrap();
        debug!("AUTHORIZATION: {}", authorization_header_value);
        info!(
            "JWT: {}",
            str::replace(authorization_header_value, "Bearer ", "")
        );
        let token_to_check = str::replace(authorization_header_value, "Bearer ", "");
        verify::check_token(server_config.public_key, token_to_check)
            .await
            .into_response()
    } else if headers.get(AUTHORIZATION).is_some() {
        debug!("got AUTHORIZATION request");
        let authorization_header_value = headers
            .get(COOKIE)
            .unwrap()
            .to_str()
            .map_err(|err| {
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(CONTENT_TYPE, "application/json".to_string())],
                    Json(serde_json::to_value(format!(
                        "Cannot parse AUTHORIZATION header value to string. Original error: {}",
                        err
                    ))),
                )
            })
            .unwrap();
        debug!("AUTHORIZATION: {}", authorization_header_value);
        info!(
            "JWT: {}",
            str::replace(authorization_header_value, "Bearer ", "")
        );
        let token_to_check = str::replace(authorization_header_value, "Bearer ", "");
        verify::check_token(server_config.public_key, token_to_check)
            .await
            .into_response()
    } else {
        error!("Nor AUTHORIZATION header, nor COOKIE value found to verify.");
        (StatusCode::UNAUTHORIZED).into_response()
    }
}

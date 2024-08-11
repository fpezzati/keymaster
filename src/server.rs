use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use log::{debug, info};
use serde_json::Value;
use std::fs;
use std::net::SocketAddr;
use tokio::net::TcpListener;

use crate::oauth2;

#[derive(Clone)]
pub struct ServerConfig {
    host: String,
    port: String,
    public_key: String,
    private_key: String,
    pub oauth2_conf: String,
}

impl ServerConfig {
    pub async fn start(config: &str) {
        println!("{}", config);
        let json_content: Value = serde_json::from_str(&config).expect("Invalid file.");
        let public_key_content = json_content["public_key"].to_string();
        let private_key_content =
            fs::read_to_string(String::from(json_content["private_key"].as_str().unwrap()))
                .unwrap();
        let server = ServerConfig {
            host: json_content["host"].as_str().unwrap().to_string(),
            port: json_content["port"].to_string(),
            public_key: public_key_content,
            private_key: private_key_content,
            oauth2_conf: json_content["oauth2_conf"].to_string(),
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
            //          .route("/verify", post(verify))
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
    oauth2::request_token(
        oauth2_config_provider,
        params.code,
        server_config.private_key,
    )
    .await
}

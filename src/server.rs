use serde_json::Value;
use serde::{ Deserialize, Serialize };
use axum::{
    extract::{Path, State, Query}, 
    http::{header::{HeaderMap, AUTHORIZATION}, StatusCode}, 
    response::IntoResponse, 
    routing::{get, post}, 
    Extension, 
    Json, 
    Router
};
use tokio::net::TcpListener;
use std::net::SocketAddr;

use crate::oauth2;

#[derive(Clone)]
pub struct ServerConfig {
    host: String,
    port: String,
    public_key: String,
    private_key: String,
    pub oauth2_conf: String
}

impl ServerConfig {
    pub async fn start(config: &str) {
        println!("{}", config);
        let json_content : Value = serde_json::from_str(&config).expect("Invalid file.");
        let server = ServerConfig {
            host: json_content["host"].as_str().unwrap().to_string(),
            port: json_content["port"].to_string(),
            public_key: json_content["public_key"].to_string(),
            private_key: json_content["private_key"].to_string(),
            oauth2_conf: json_content["oauth2_conf"].to_string()
        };

        let mut hostport = String::new();
        hostport.push_str(server.host.as_str());
        hostport.push_str(":");
        hostport.push_str(server.port.as_str());
        println!("hostport: {}", hostport);
        let server_socket = hostport.parse::<SocketAddr>().expect("invalid host:port pair");

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

pub async fn callback(
    State(server_config): State<ServerConfig>,
    Path(id_provider): Path<String>,
    Query(code): Query<String>
) -> impl IntoResponse {
    println!("id_provider: {}", id_provider.as_str());
    let oauth2_config: Value = serde_json::from_str(server_config.oauth2_conf.as_str()).expect("Invalid configuration.");
    let oauth2_config_provider = oauth2_config[id_provider.as_str()].clone();
    let temporary_output = oauth2_config[id_provider.as_str()].clone();
    oauth2::request_token(oauth2_config_provider, code);
    (StatusCode::OK, Json(serde_json::to_value(temporary_output).unwrap()))
}
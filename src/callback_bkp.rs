use axum::{
    Json,
    extract::{Query, Extension, State},
    http::StatusCode,
    response::IntoResponse
};
use serde_json::{json, Value};
use hyper::{self, header};
use hyper_tls::HttpsConnector;
use cookie::Cookie;
use serde::{Deserialize, Serialize};
use http::header::HeaderName;
use jwt_simple::claims::Claims;
use jwt_simple::prelude::{Duration, RS384KeyPair};

#[derive(Clone)]
pub struct OAuth2Conf {
    client_id: String,
    redirect_uri: String,
    client_secret: String,
    idp_url: String,
}

#[derive(Serialize, Deserialize)]
pub struct CallbackAuthCode {
    code: String
}

impl OAuth2Conf {
    pub fn new(conf: &str) -> OAuth2Conf {
        let json_content: Value = serde_json::from_str(conf).expect("Invalid configuration.");
        OAuth2Conf {
            client_id: json_content["client_id"].as_str().unwrap().to_string(),
            redirect_uri: json_content["redirect_uri"].as_str().unwrap().to_string(),
            client_secret: json_content["client_secret"].as_str().unwrap().to_string(),
            idp_url: json_content["idp_url"].as_str().unwrap().to_string()
        }
    }
}

pub async fn callback(
    State(server): State<Server>,
    Path(path_params): Path<String>,
    Query(params): Query<CallbackAuthCode>,
    Extension(conf): Extension<OAuth2Conf>
) -> impl IntoResponse {
    let token_url = format!(
        "{}?client_id={}&redirect_uri={}&client_secret={}&code={}",
        conf.idp_url, conf.client_id, conf.redirect_uri, conf.client_secret, params.code
    );

    let client = hyper::Client::builder()
        .build::<_, hyper::Body>(HttpsConnector::new());

    let req = hyper::Request::builder()
        .method(hyper::Method::POST)
        .uri(token_url)
        .header("Accept", "application/json")
        .body(hyper::Body::empty())
        .unwrap();

    match client.request(req).await {
        Ok(resp) => {
            if resp.status().is_redirection() {
                handle_redirect(client, resp).await
            } else {
                build_error_response(StatusCode::BAD_GATEWAY, "Unexpected response from service.".to_string())
            }
        }
        Err(e) => build_error_response(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

async fn handle_redirect(client: hyper::Client<HttpsConnector<hyper::client::connect::HttpConnector>>, resp: hyper::Response<hyper::Body>) -> impl IntoResponse {
    if let Some(location) = resp.headers().get(header::LOCATION) {
        let redirect_uri = location.to_str().unwrap();
        let redirect_req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(redirect_uri)
            .header("Accept", "application/json")
            .body(hyper::Body::empty())
            .unwrap();

        match client.request(redirect_req).await {
            Ok(mut redirect_resp) => {
                let body = hyper::body::to_bytes(redirect_resp.body_mut()).await.unwrap();
                let body_as_json: Value = serde_json::from_slice(&body).unwrap();
                let bearer_token = body_as_json["access_token"].as_str().unwrap().to_string();

                let cookie = Cookie::build("hey", &bearer_token)
                    .secure(true)
                    .http_only(true)
                    .finish();

                let pkey = RS384KeyPair::from_pem(server.private_key.as_str()).unwrap();
                let unsigned_claims = Claims::with_custom_claims(
                    UserClaims {
                        user: "jimmy".to_string(),
                        auth_provider: "github".to_string(),
                        token: bearer_token.clone(),
                    },
                    Duration::from_hours(1),
                );

                let signed_claims = pkey.sign(unsigned_claims).unwrap();
                (
                    StatusCode::OK,
                    [(header::SET_COOKIE, signed_claims)],
                    Json(json!({ "user": "got that cookie" })),
                )
            }
            Err(redirect_e) => build_error_response(StatusCode::INTERNAL_SERVER_ERROR, redirect_e.to_string()),
        }
    } else {
        build_error_response(StatusCode::BAD_GATEWAY, "Missing Location header in redirect response.".to_string())
    }
}

#[derive(Serialize, Deserialize)]
struct ErrorResponsePayload {
    error: String
}

fn build_error_response(status_code: StatusCode, error_msg: String) -> (StatusCode, [(HeaderName, String); 1], Json<Value>) {
    let error_msg_as_json = ErrorResponsePayload { error: error_msg };
    (
        status_code,
        [(header::CONTENT_TYPE, "application/json".to_string())],
        Json(serde_json::to_value(error_msg_as_json).unwrap())
    )
}

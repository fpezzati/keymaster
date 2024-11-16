use axum::{
    http::{
        header::{AUTHORIZATION, COOKIE},
        HeaderMap, StatusCode,
    },
    response::IntoResponse,
};
use jwt_simple::algorithms::RS384PublicKey;
use jwt_simple::algorithms::RSAPublicKeyLike;
use log::{debug, info};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct UserClaims {
    user: String,
    auth_provider: String,
    token: String,
}

pub async fn check_token(public_key: String, headers: HeaderMap) -> impl IntoResponse {
    let authorization_header_value = headers.get(AUTHORIZATION).unwrap().to_str().unwrap();
    debug!("AUTHORIZATION: {}", authorization_header_value);
    info!(
        "JWT: {}",
        str::replace(authorization_header_value, "Bearer ", "")
    );

    let token_to_check = str::replace(authorization_header_value, "Bearer ", "");
    let token_checker = RS384PublicKey::from_pem(public_key.as_str()).unwrap();
    match token_checker.verify_token::<UserClaims>(&token_to_check, None) {
        Ok(_claims) => StatusCode::OK,
        Err(_error) => StatusCode::UNAUTHORIZED,
    }
}

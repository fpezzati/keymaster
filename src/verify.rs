use axum::{http::StatusCode, response::IntoResponse};
use jwt_simple::algorithms::RS384PublicKey;
use jwt_simple::algorithms::RSAPublicKeyLike;
use log::{error, info};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct UserClaims {
    user: String,
    auth_provider: String,
    token: String,
}

pub async fn check_token(public_key: String, token_to_check: String) -> impl IntoResponse {
    info!(
        "Verifying token: {}, with public key: {}",
        token_to_check, public_key
    );
    let token_checker = RS384PublicKey::from_pem(public_key.as_str())
        .map_err(|err| error!("Invalid key. Original error: {}", err))
        .unwrap();
    match token_checker.verify_token::<UserClaims>(&token_to_check, None) {
        Ok(_claims) => StatusCode::OK,
        Err(_error) => {
            info!("Cannot validate given token. Original error: {}", _error);
            StatusCode::UNAUTHORIZED
        }
    }
}

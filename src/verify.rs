use crate::server::ServerError;
use crate::server::UserClaims;
use jwt_simple::algorithms::RS384PublicKey;
use jwt_simple::algorithms::RSAPublicKeyLike;
use log::{error, info};

pub async fn check_token(public_key: String, token_to_check: String) -> Result<bool, ServerError> {
    info!(
        "Verifying token: {}, with public key: {}",
        token_to_check, public_key
    );
    let token_to_check_values: Vec<&str> = token_to_check.split("=").collect();
    let token_checker = RS384PublicKey::from_pem(public_key.as_str()).map_err(|err| {
        error!("Invalid key. Original error: {}", err);
        return ServerError {
            message: format!("Invalid key. Original error: {}", err).to_string(),
            http_code: 401,
        };
    })?;
    match token_checker.verify_token::<UserClaims>(&token_to_check_values[1], None) {
        Ok(_) => Ok(true),
        Err(err) => {
            info!("Cannot validate given token. Original error: {}", err);
            Err(ServerError {
                message: format!("Cannot validate given token. Original error: {}", err)
                    .to_string(),
                http_code: 401,
            })
        }
    }
}

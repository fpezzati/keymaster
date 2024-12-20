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
}

impl OAuth2Conf {
    pub fn new(conf: Value) -> OAuth2Conf {
        OAuth2Conf {
            client_id: conf["client_id"].as_str().unwrap().to_string(),
            redirect_uri: conf["redirect_uri"].as_str().unwrap().to_string(),
            client_secret: conf["client_secret"].as_str().unwrap().to_string(),
            idp_url: conf["idp_url"].as_str().unwrap().to_string(),
        }
    }
}

pub async fn request_token(oauth2_conf: Value, code: String, private_key: String) -> Response {
    let conf = OAuth2Conf::new(oauth2_conf);
    let token_url = format!(
        "{}?client_id={}&client_secret={}&code={}&redirect_uri={}&response_type=code&scope=userinfo.email",
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
                match resp.text().await {
                    Ok(text_body) => {
                        debug!("Got response that should contains token in body: {text_body}");
                        let json_body =
                            serde_json::from_str::<serde_json::Value>(text_body.as_str()).unwrap();
                        return pick_token_and_provides_response(json_body, private_key);
                    }
                    Err(e) => {
                        error!("Something wrong while reading response. Original error: {e}");
                        return build_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!(
                                "Something wrong while reading response. Original error: {}",
                                e
                            )
                            .to_string(),
                        );
                    }
                }
                //                match resp.json::<Value>().await {
                //                    Ok(json_body) => {
                //                        debug!("request went fine.");
                //                        return pick_token_and_provides_response(json_body, private_key);
                //                    }
                //                    Err(e) => {
                //                        // no token, raise error
                //                        let resp_body = resp.text().await.unwrap();
                //                        error!("No token, error returned. Response was: {resp_body}");
                //                        return build_error_response(
                //                            StatusCode::INTERNAL_SERVER_ERROR,
                //                            format!("No token found. Original error: {}", e).to_string(),
                //                        );
                //                    }
            } else if resp.status() == 301 {
                debug!("Redirect detected.");
                let redirect_uri: String = resp
                    .headers()
                    .get("Location")
                    .unwrap()
                    .to_str()
                    .unwrap()
                    .to_string();
                match client
                    .post(redirect_uri.as_str())
                    .header("Accept", "application/json")
                    .send()
                    .await
                {
                    Ok(redirect_resp) => {
                        debug!("Redirect went fine.");
                        match redirect_resp.json::<Value>().await {
                            Ok(redirect_body) => {
                                debug!("Getting token from redirect.");
                                return pick_token_and_provides_response(
                                    redirect_body,
                                    private_key,
                                );
                            }
                            Err(redirect_err) => {
                                // something is wrong with redirect reply, raise error
                                error!("Error while getting redirect response body.");
                                return build_error_response(
                                    StatusCode::INTERNAL_SERVER_ERROR,
                                    format!("No token found. Original error: {}", redirect_err)
                                        .to_string(),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        // redirect went wrong, raise error
                        error!("Redirect went wrong.");
                        return build_error_response(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            format!("No token found. Original error: {}", e).to_string(),
                        );
                    }
                }
            } else {
                // get token went wrong, raise error
                let resp_body = resp.text().await.unwrap();
                error!("Getting token went wrong, Idp provider replies with an error: {resp_body}");
                return build_error_response(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Error while fetching token. Original response: {}",
                        resp_body
                    ),
                );
            }
        }
        Err(err) => {
            error!("Token request went wrong.");
            return build_error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error while fetching token. Original error: {}", err).to_string(),
            );
        }
    }
}

#[derive(Serialize, Deserialize)]
struct UserClaims {
    user: String,
    auth_provider: String,
    token: String,
}

fn pick_token_and_provides_response(body_as_json: Value, private_key: String) -> Response {
    debug!("Body from which to pick access token: {body_as_json}");
    let token = body_as_json["access_token"].as_str().unwrap();
    let cookie = Cookie::build(("hey", token))
        .secure(true)
        .http_only(true)
        .build();
    let cookie_value = String::from(cookie.value());
    let pkey = RS384KeyPair::from_pem(private_key.as_str()).unwrap();

    let unsigned_claims = Claims::with_custom_claims(
        UserClaims {
            user: String::from("jimmy"),
            auth_provider: String::from("github"),
            token: token.to_string(),
        },
        Duration::from_hours(1),
    );
    let signed_claims = pkey.sign(unsigned_claims).unwrap();

    return (
        StatusCode::OK,
        [
            (header::SET_COOKIE, signed_claims),
            (header::CONTENT_TYPE, "application/json".to_string()),
        ],
        Json(json!({
          "msg": cookie_value
        })),
    )
        .into_response();
}

fn build_error_response(status_code: StatusCode, error_msg: String) -> Response {
    #[derive(Serialize, Deserialize)]
    struct ErrorResponsePayload {
        error: String,
    }

    let error_msg_as_json = ErrorResponsePayload { error: error_msg };
    return (
        status_code,
        [(header::CONTENT_TYPE, "application/json".to_string())],
        Json(serde_json::to_value(error_msg_as_json).unwrap()),
    )
        .into_response();
}

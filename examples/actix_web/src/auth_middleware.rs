use actix_web::{
    Error, HttpMessage, HttpResponse,
    body::{EitherBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
    web::Data,
};
use serde_json::json;

use crate::AppState;

pub async fn auth_middleware<B>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<EitherBody<B>>, Error>
where
    B: MessageBody + 'static,
{
    let state = req
        .app_data::<Data<AppState>>()
        .expect("AppState must be registered")
        .clone();

    let token = match req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
    {
        Some(token) => token.to_owned(),
        None => {
            return Ok(req.into_response(
                HttpResponse::Unauthorized()
                    .json(json!({
                        "success": false,
                        "message": "Missing bearer token"
                    }))
                    .map_into_right_body(),
            ));
        }
    };

    let claims = {
        let auth = state.auth.lock().await;

        match auth.is_token_valid(&token).await {
            Ok(claims) => claims,
            Err(_) => {
                return Ok(req.into_response(
                    HttpResponse::Unauthorized()
                        .json(json!({
                            "success": false,
                            "message": "Invalid token"
                        }))
                        .map_into_right_body(),
                ));
            }
        }
    };

    req.extensions_mut().insert(claims);

    let res = next.call(req).await?;
    Ok(res.map_into_left_body())
}

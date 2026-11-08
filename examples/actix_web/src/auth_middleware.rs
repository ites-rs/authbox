use actix_web::{
    Error, HttpMessage, HttpResponse,
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
    web::Data,
};
use serde_json::json;

use crate::AppState;

pub async fn auth_middleware<B>(
    req: ServiceRequest,
    next: Next<B>,
) -> Result<ServiceResponse<BoxBody>, Error>
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
            return Ok(req.into_response(HttpResponse::Unauthorized().json(json!({
                "success": false,
                "message": "Missing bearer token"
            }))));
        }
    };

    let claims = match state.auth.is_token_valid(&token).await {
        Ok(claims) => claims,
        Err(_) => {
            return Ok(req.into_response(HttpResponse::Unauthorized().json(json!({
                "success": false,
                "message": "Invalid token"
            }))));
        }
    };

    // handlers can read these with web::ReqData<Claims> if they need them
    req.extensions_mut().insert(claims);

    let res = next.call(req).await?;
    Ok(res.map_into_boxed_body())
}

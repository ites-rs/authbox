use crate::infrastructure::state::AppState;
use actix_web::{
    Error, HttpMessage, HttpResponse,
    body::{BoxBody, MessageBody},
    dev::{ServiceRequest, ServiceResponse},
    middleware::Next,
    web::Data,
};
use serde_json::json;

/// Validates the Bearer token on every request that hits a protected route.
/// On success it injects the Claims into request extensions so handlers can
/// grab them with `web::ReqData<Claims>` without touching the token again.
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
        Some(t) => t.to_owned(),
        None => {
            return Ok(req.into_response(HttpResponse::Unauthorized().json(json!({
                "success": false,
                "message": "Missing bearer token"
            }))));
        }
    };

    let claims = match state.auth.is_token_valid(&token).await {
        Ok(c) => c,
        Err(_) => {
            return Ok(req.into_response(HttpResponse::Unauthorized().json(json!({
                "success": false,
                "message": "Invalid or expired token"
            }))));
        }
    };

    req.extensions_mut().insert(claims);
    let res = next.call(req).await?;
    Ok(res.map_into_boxed_body())
}

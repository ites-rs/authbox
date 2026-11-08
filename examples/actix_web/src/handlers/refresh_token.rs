use crate::AppState;
use crate::models::RefreshRequest;
use actix_web::{HttpResponse, Responder, post, web};
use serde_json::json;

#[post("/refresh")]
pub async fn refresh(
    state: web::Data<AppState>,
    body: web::Json<RefreshRequest>,
) -> impl Responder {
    match state.auth.refresh_token(&body.refresh_token).await {
        Ok(tokens) => HttpResponse::Ok().json(json!({
            "access": tokens.access_token,
            "refresh": tokens.refresh_token
        })),
        Err(e) => HttpResponse::Unauthorized().json(json!({
            "error": format!("{:?}", e)
        })),
    }
}

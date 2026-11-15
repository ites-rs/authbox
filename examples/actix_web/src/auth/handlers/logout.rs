use crate::{auth::models::LogOutRequest, infrastructure::state::AppState};
use actix_web::{HttpResponse, Responder, post, web};
use authbox::prelude::Claims;
use serde_json::json;

#[post("/logout")]
pub async fn logout(state: web::Data<AppState>, body: web::Json<LogOutRequest>) -> impl Responder {
    match state.auth.logout(&body.refresh_token).await {
        Ok(_) => HttpResponse::Ok().json(json!({
            "success": true,
            "message": "Logged out successfully"
        })),
        Err(e) => HttpResponse::Unauthorized().json(json!({
            "success": false,
            "error": format!("{:?}", e)
        })),
    }
}

// protected — requires a valid access token via auth_middleware
#[post("/logout/all")]
pub async fn logout_all(
    state: web::Data<AppState>,
    claims: web::ReqData<Claims>,
) -> impl Responder {
    match state.auth.logout_all(&claims.sub).await {
        Ok(_) => HttpResponse::Ok().json(json!({
            "success": true,
            "message": "All sessions revoked"
        })),
        Err(e) => HttpResponse::InternalServerError().json(json!({
            "success": false,
            "error": format!("{:?}", e)
        })),
    }
}

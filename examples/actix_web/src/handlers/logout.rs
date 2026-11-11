use crate::AppState;
use crate::models::LogOutRequest;
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

#[post("/logout/all")]
pub async fn logout_all(
    state: web::Data<AppState>,
    claims: web::ReqData<Claims>,
) -> impl Responder {
    match state.auth.logout_all(&claims.sub).await {
        Ok(_) => HttpResponse::Ok().json(json!({
            "success": true,
            "message": "Logged out all sessions successfully"
        })),
        Err(e) => HttpResponse::Unauthorized().json(json!({
            "success": false,
            "error": format!("{:?}", e)
        })),
    }
}

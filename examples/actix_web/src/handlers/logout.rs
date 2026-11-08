use crate::AppState;
use crate::models::LogOutRequest;
use actix_web::{HttpResponse, Responder, post, web};
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

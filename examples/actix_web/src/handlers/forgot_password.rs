use crate::AppState;
use crate::models::ForgotPasswordRequest;
use actix_web::{HttpResponse, Responder, post, web};
use serde_json::json;

#[post("/forgot-password")]
pub async fn forgot_password(
    state: web::Data<AppState>,
    body: web::Json<ForgotPasswordRequest>,
) -> impl Responder {
    match state.auth.request_password_reset(&body.email).await {
        Ok(_) => HttpResponse::Ok().json(json!({
            "success": true,
            "message": "Password reset requested"
        })),
        Err(e) => HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": format!("{:?}", e)
        })),
    }
}

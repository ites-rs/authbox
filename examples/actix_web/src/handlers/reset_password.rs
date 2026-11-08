use crate::AppState;
use crate::models::ResetPasswordRequest;
use actix_web::{HttpResponse, Responder, post, web};
use serde_json::json;

#[post("/reset-password")]
pub async fn reset_password(
    state: web::Data<AppState>,
    body: web::Json<ResetPasswordRequest>,
) -> impl Responder {
    match state.auth.reset_password(&body.token, &body.password).await {
        Ok(_) => HttpResponse::Ok().json(json!({
            "success": true,
            "message": "Password updated successfully"
        })),
        Err(e) => HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": format!("{:?}", e)
        })),
    }
}

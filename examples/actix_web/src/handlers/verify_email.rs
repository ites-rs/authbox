use crate::AppState;
use crate::models::VerifyEmailRequest;
use actix_web::{HttpResponse, Responder, post, web};
use serde_json::json;

#[post("/verify-email")]
pub async fn verify_email(
    state: web::Data<AppState>,
    body: web::Json<VerifyEmailRequest>,
) -> impl Responder {
    match state.auth.verify_email(&body.token).await {
        Ok(_) => HttpResponse::Ok().json(json!({
            "success": true,
            "message": "Email verified successfully"
        })),
        Err(e) => HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": format!("{:?}", e)
        })),
    }
}

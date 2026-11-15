use crate::{auth::models::ResendVerificationRequest, infrastructure::state::AppState};
use actix_web::{HttpResponse, Responder, post, web};
use serde_json::json;

#[post("/resend-verification")]
pub async fn request_verify_email(
    state: web::Data<AppState>,
    body: web::Json<ResendVerificationRequest>,
) -> impl Responder {
    // always 200 — we never reveal whether the address is registered
    let _ = state.auth.request_verify_email(&body.email).await;
    HttpResponse::Ok().json(json!({
        "success": true,
        "message": "If that address is registered and unverified, a new email is on its way"
    }))
}

use crate::{auth::models::ForgotPasswordRequest, infrastructure::state::AppState};
use actix_web::{HttpResponse, Responder, post, web};
use serde_json::json;

#[post("/forgot-password")]
pub async fn forgot_password(
    state: web::Data<AppState>,
    body: web::Json<ForgotPasswordRequest>,
) -> impl Responder {
    // always 200 — we never reveal whether the address is registered
    let _ = state.auth.request_password_reset(&body.email).await;
    HttpResponse::Ok().json(json!({
        "success": true,
        "message": "If that address is registered, a reset email is on its way"
    }))
}

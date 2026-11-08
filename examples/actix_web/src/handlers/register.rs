use crate::AppState;
use crate::common::*;
use actix_web::{HttpResponse, Responder, post, web};
use authbox::prelude::AuthError;
use serde_json::json;

#[post("/register")]
pub async fn register(state: web::Data<AppState>, body: web::Json<RegisterDto>) -> impl Responder {
    match state.auth.register(&*body).await {
        Ok(user) => HttpResponse::Created().json(json!({
            "id": user.id(),
            "email": user.email(),
            "verified": user.is_email_verified()
        })),
        Err(AuthError::EmailAlreadyExists) => HttpResponse::Conflict().json(json!({
            "error": "email already registered"
        })),
        Err(e) => HttpResponse::BadRequest().json(json!({
            "error": format!("{:?}", e)
        })),
    }
}

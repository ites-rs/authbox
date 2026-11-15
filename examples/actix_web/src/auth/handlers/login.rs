use crate::{auth::models::LoginRequest, infrastructure::state::AppState};
use actix_web::{HttpResponse, Responder, post, web};
use serde_json::json;

#[post("/login")]
pub async fn login(state: web::Data<AppState>, body: web::Json<LoginRequest>) -> impl Responder {
    match state.auth.login(&body.email, &body.password).await {
        Ok(tokens) => HttpResponse::Ok().json(tokens),
        Err(e) => HttpResponse::Unauthorized().json(json!({
            "error": format!("{:?}", e)
        })),
    }
}

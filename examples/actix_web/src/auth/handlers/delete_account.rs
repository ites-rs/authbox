use crate::{auth::models::DeleteAccountRequest, infrastructure::state::AppState};
use actix_web::{HttpResponse, Responder, post, web};
use authbox::prelude::{AuthError, Claims};
use serde_json::json;

#[post("/delete-account")]
pub async fn delete_account(
    state: web::Data<AppState>,
    claims: web::ReqData<Claims>,
    body: web::Json<DeleteAccountRequest>,
) -> impl Responder {
    match state.auth.delete_account(&claims.sub, &body.password).await {
        Ok(_) => HttpResponse::Ok().json(json!({
            "success": true,
            "message": "Account deleted"
        })),
        Err(AuthError::InvalidCredentials) => HttpResponse::Unauthorized().json(json!({
            "success": false,
            "error": "password is incorrect"
        })),
        Err(e) => HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": format!("{:?}", e)
        })),
    }
}

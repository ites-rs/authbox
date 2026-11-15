use crate::{auth::models::ChangePasswordRequest, infrastructure::state::AppState};
use actix_web::{HttpResponse, Responder, post, web};
use authbox::prelude::{AuthError, Claims};
use serde_json::json;

// user_id always comes from the validated claims, never from the request body
#[post("/change-password")]
pub async fn change_password(
    state: web::Data<AppState>,
    claims: web::ReqData<Claims>,
    body: web::Json<ChangePasswordRequest>,
) -> impl Responder {
    match state
        .auth
        .change_password(&claims.sub, &body.old_password, &body.new_password)
        .await
    {
        Ok(_) => HttpResponse::Ok().json(json!({
            "success": true,
            "message": "Password changed. Please log in again with your new password."
        })),
        Err(AuthError::InvalidCredentials) => HttpResponse::Unauthorized().json(json!({
            "success": false,
            "error": "current password is incorrect"
        })),
        Err(e) => HttpResponse::BadRequest().json(json!({
            "success": false,
            "error": format!("{:?}", e)
        })),
    }
}

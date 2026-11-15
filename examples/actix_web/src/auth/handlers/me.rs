use crate::infrastructure::state::AppState;
use actix_web::{HttpRequest, HttpResponse, Responder, get, web};
use authbox::prelude::Claims;

fn bearer_token(req: &HttpRequest) -> Option<&str> {
    req.headers()
        .get("Authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

// Claims are already validated by auth_middleware, but auth.me() re-validates
// internally so the response always reflects the latest blacklist state.
#[get("/me")]
pub async fn me(
    state: web::Data<AppState>,
    req: HttpRequest,
    _claims: web::ReqData<Claims>,
) -> impl Responder {
    let Some(token) = bearer_token(&req) else {
        return HttpResponse::Unauthorized().finish();
    };

    match state.auth.me(token).await {
        Ok(me) => HttpResponse::Ok().json(me),
        Err(_) => HttpResponse::Unauthorized().finish(),
    }
}

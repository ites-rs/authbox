use crate::AppState;
use actix_web::{HttpRequest, HttpResponse, Responder, get, web};

// pulls the token out of an "Authorization: Bearer <token>" header
fn bearer_token(req: &HttpRequest) -> Option<&str> {
    req.headers()
        .get("Authorization")?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

#[get("/me")]
pub async fn me(state: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let Some(token) = bearer_token(&req) else {
        return HttpResponse::Unauthorized().finish();
    };

    match state.auth.me(token).await {
        Ok(me) => HttpResponse::Ok().json(me),
        Err(_) => HttpResponse::Unauthorized().finish(),
    }
}

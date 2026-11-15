use actix_web::{HttpResponse, Responder, get};

#[get("/")]
pub async fn index() -> impl Responder {
    HttpResponse::Ok().body("OK")
}

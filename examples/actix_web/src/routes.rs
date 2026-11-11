use super::auth_middleware::auth_middleware;
use crate::handlers::{
    forgot_password::forgot_password, index::index, login::login, logout::logout, logout_all,
    me::me, refresh_token::refresh, register::register, reset_password::reset_password,
    verify_email::verify_email,
};
use actix_web::{middleware::from_fn, web};

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg.service(index)
        .service(register)
        .service(login)
        .service(refresh)
        .service(verify_email)
        .service(forgot_password)
        .service(logout)
        .service(reset_password)
        .service(
            web::scope("/api")
                .wrap(from_fn(auth_middleware))
                .service(logout_all)
                .service(me),
        );
}

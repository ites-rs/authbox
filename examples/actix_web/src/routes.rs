use crate::auth::{
    handlers::{
        change_password::change_password,
        delete_account::delete_account,
        forgot_password::forgot_password,
        login::login,
        logout::{logout, logout_all},
        me::me,
        refresh_token::refresh,
        register::register,
        request_verify_email::request_verify_email,
        reset_password::reset_password,
        verify_email::verify_email,
    },
    middleware::auth_middleware,
};
use actix_web::{middleware::from_fn, web};

pub fn config(cfg: &mut web::ServiceConfig) {
    cfg
        // public — no token required
        .service(register)
        .service(login)
        .service(refresh)
        .service(verify_email)
        .service(request_verify_email)
        .service(forgot_password)
        .service(logout)
        .service(reset_password)
        // protected — auth_middleware validates the bearer token and injects
        // Claims into request extensions before each handler runs
        .service(
            web::scope("/api")
                .wrap(from_fn(auth_middleware))
                .service(me)
                .service(logout_all)
                .service(change_password)
                .service(delete_account),
        );
}

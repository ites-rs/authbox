use actix_web::{App, HttpServer, dev::Server, web};

mod auth_middleware;
mod common;
mod email_providers;
mod handlers;
mod models;
mod routes;

use common::*;

use routes::config;

pub struct AppState {
    pub auth: tokio::sync::Mutex<TestAuthService>,
}

pub fn server() -> Result<Server, std::io::Error> {
    println!("Server running at http://127.0.0.1:8080");

    let state = web::Data::new(AppState {
        auth: tokio::sync::Mutex::new(build_test_auth()),
    });

    let server = HttpServer::new(move || App::new().app_data(state.clone()).configure(config))
        .bind(("127.0.0.1", 8080))?
        .run();

    Ok(server)
}

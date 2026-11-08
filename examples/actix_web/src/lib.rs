use actix_web::{App, HttpServer, dev::Server, web};
use authbox::prelude::AuthService;

mod auth_middleware;
mod common;
mod email_providers;
mod handlers;
mod models;
mod routes;

use common::*;

use routes::config;

pub struct AppState {
    pub auth: AuthService,
}

pub async fn server() -> Result<Server, std::io::Error> {
    // build the auth service first; the redis stores are created asynchronously
    let auth = build_test_auth().await.map_err(std::io::Error::other)?;

    let state = web::Data::new(AppState { auth });

    let server = HttpServer::new(move || App::new().app_data(state.clone()).configure(config))
        .bind(("127.0.0.1", 8080))?
        .run();

    println!("Server running at http://127.0.0.1:8080");

    Ok(server)
}

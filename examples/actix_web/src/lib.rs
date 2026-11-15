mod auth;
mod infrastructure;
mod routes;

use actix_web::{App, HttpServer, dev::Server, web};
use auth::common::build_test_auth;
use infrastructure::state::AppState;
use routes::config;

pub async fn server() -> Result<Server, std::io::Error> {
    let auth = build_test_auth().await.map_err(std::io::Error::other)?;
    let state = web::Data::new(AppState { auth });

    let server = HttpServer::new(move || App::new().app_data(state.clone()).configure(config))
        .bind(("127.0.0.1", 8080))?
        .run();

    println!("Server running at http://127.0.0.1:8080");
    Ok(server)
}

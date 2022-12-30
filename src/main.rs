use argon2::{self, Config};
use axum::{
    extract::Form,
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use serde::Deserialize;
use std::net::SocketAddr;
use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

#[tokio::main]
async fn main() {
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "example_form=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    let app = Router::new().route("/", get(show_form).post(accept_form));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));
    tracing::debug!("listening on {}", addr);
    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn show_form() -> Html<&'static str> {
    Html(std::include_str!("../login.html"))
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Input {
    password: String,
}

async fn accept_form(Form(input): Form<Input>) -> impl IntoResponse {
    let password = b"test";
    let salt = b"D;%yL9TS:5PalS/d";
    let config = Config::default();
    let hash = argon2::hash_encoded(password, salt, &config).unwrap();
    let matches = argon2::verify_encoded(&hash, input.password.as_bytes()).unwrap();

    match matches {
        true => Response::builder()
            .status(http::StatusCode::OK)
            .header("authenticated", "yes")
            .body(include_str!("../home.html").to_owned())
            .unwrap(),
        false => Response::builder()
            .status(http::StatusCode::OK)
            .header("authenticated", "no")
            .body(include_str!("../incorrect-password.html").to_owned())
            .unwrap(),
    }
}

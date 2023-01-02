use argon2::{self, Config};
use axum::{
    extract::Form,
    response::{Html, IntoResponse},
    routing::get,
    Router,
};
use axum_sessions::{
    async_session::MemoryStore,
    extractors::{ReadableSession, WritableSession},
    SessionLayer,
};
use rand::Rng;
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

    let store = MemoryStore::new();
    let mut secret = [0u8; 128];
    rand::thread_rng().fill(&mut secret);
    let session_layer = SessionLayer::new(store, &secret).with_cookie_name("session");

    let app = Router::new()
        .route("/", get(show_form).post(authenticate))
        .route("/redirect.html", get(redirect))
        .layer(session_layer);

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

async fn authenticate(mut session: WritableSession, Form(input): Form<Input>) -> impl IntoResponse {
    let password = b"test";
    let salt = b"D;%yL9TS:5PalS/d";
    let config = Config::default();
    let hash = argon2::hash_encoded(password, salt, &config).unwrap();
    let matches = argon2::verify_encoded(&hash, input.password.as_bytes()).unwrap();

    match matches {
        true => {
            session
                .insert("signed_in", true)
                .expect("authentication error");
            Html(std::include_str!("../home.html"))
        }
        false => {
            session
                .insert("signed_in", false)
                .expect("authentication error");
            Html(std::include_str!("../incorrect-password.html"))
        }
    }
}

async fn redirect(session: ReadableSession) -> impl IntoResponse {
    if session.get::<bool>("signed_in").unwrap_or(false) {
        Html(std::include_str!("../redirect.html"))
    } else {
        Html("You are not logged in")
    }
}

use argon2::{self, Config};
use axum::{
    body::{boxed, Body, BoxBody},
    extract::Form,
    headers::Cookie,
    http::{Request, StatusCode, Uri},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router, TypedHeader,
};
use http::header::{LOCATION, SET_COOKIE};
use http_body::Empty;
use serde::Deserialize;
use std::{error::Error, fmt, net::SocketAddr};
use tower::ServiceExt;
use tower_http::services::ServeDir;

#[derive(Debug)]
struct Unauthenticated {
    details: String,
}

impl Unauthenticated {
    fn new(msg: &str) -> Unauthenticated {
        Unauthenticated {
            details: msg.to_string(),
        }
    }
}

impl fmt::Display for Unauthenticated {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.details)
    }
}

impl Error for Unauthenticated {
    fn description(&self) -> &str {
        &self.details
    }
}

impl IntoResponse for Unauthenticated {
    fn into_response(self) -> Response {
        Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(axum::body::boxed(String::from("unauthorized")))
            .unwrap()
    }
}

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(show_form).post(authenticate))
        .nest_service("/authenticated", get(is_authenticated));

    let addr = SocketAddr::from(([127, 0, 0, 1], 3000));

    axum::Server::bind(&addr)
        .serve(app.into_make_service())
        .await
        .unwrap();
}

async fn show_form() -> Html<&'static str> {
    Html(std::include_str!("../assets/login.html"))
}

async fn is_authenticated(
    uri: Uri,
    TypedHeader(cookie): TypedHeader<Cookie>,
) -> Result<Response<BoxBody>, Unauthenticated> {
    let request = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let service = ServeDir::new("assets/authenticated");

    let cookie = cookie.get("authenticated").unwrap();

    if cookie != "yes" {
        Err(Unauthenticated::new("unauthenticated"))
    } else {
        match service.oneshot(request).await {
            Ok(res) => Ok(res.map(boxed)),
            Err(_) => Err(Unauthenticated::new("Something went wrong...")),
        }
    }
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct Input {
    password: String,
}

async fn authenticate(Form(input): Form<Input>) -> impl IntoResponse {
    let password = b"test";
    let salt = b"D;%yL9TS:5PalS/d";
    let config = Config::default();
    let hash = argon2::hash_encoded(password, salt, &config).unwrap();
    let matches = argon2::verify_encoded(&hash, input.password.as_bytes()).unwrap();

    match matches {
        true => Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(LOCATION, "/authenticated")
            .header(SET_COOKIE, "authenticated=yes")
            .body(Empty::new())
            .unwrap(),
        false => Response::builder()
            .status(StatusCode::SEE_OTHER)
            .header(LOCATION, "/authenticated")
            .header(SET_COOKIE, "authenticated=no")
            .body(Empty::new())
            .unwrap(),
    }
}

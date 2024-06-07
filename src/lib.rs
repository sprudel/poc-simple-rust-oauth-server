use axum::Router;
use axum::routing::get;

pub fn create_app() -> Router {
    Router::new().route("/", get(root))
}
// basic handler that responds with a static string
async fn root() -> &'static str {
    "Hello, World!"
}

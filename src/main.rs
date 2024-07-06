use simple_oauth_server::create_app;
use tower_http::trace::TraceLayer;
use url::Url;

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();
    let trace_layer = TraceLayer::new_for_http();

    // run our app with hyper
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    // build our application with a route
    let app = create_app(Url::parse("http://localhost:3000").unwrap()).layer(trace_layer);
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

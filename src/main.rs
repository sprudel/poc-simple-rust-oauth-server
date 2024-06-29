use axum::handler::Handler;
use simple_oauth_server::create_app;
use tower_http::trace::TraceLayer;

#[tokio::main]
async fn main() {
    // initialize tracing
    tracing_subscriber::fmt::init();
    let trace_layer = TraceLayer::new_for_http();

    // build our application with a route
    let app = create_app().layer(trace_layer);

    // run our app with hyper
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

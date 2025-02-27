use dotenv::dotenv;
use simple_oauth_server::{create_app, create_config};
use sqlx::postgres::PgPoolOptions;
use tower_http::trace::TraceLayer;
use url::Url;

#[tokio::main]
async fn main() {
    dotenv().ok();

    // initialize tracing
    tracing_subscriber::fmt::init();
    let trace_layer = TraceLayer::new_for_http();

    tracing::info!("Running db migrations");
    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&std::env::var("DATABASE_URL").unwrap())
        .await
        .unwrap();
    sqlx::migrate!().run(&pool).await.unwrap();
    tracing::info!("Completed db migrations");

    // run our app with hyper
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    // build our application with a route
    let app = create_app(
        create_config(Url::parse("http://localhost:3000").unwrap()),
        pool,
    )
    .layer(trace_layer);
    tracing::info!("listening on {}", listener.local_addr().unwrap());
    axum::serve(listener, app).await.unwrap();
}

default:
   just --list

run: start-test-environment
    RUST_LOG=info cargo run

commit *FLAGS:
  cargo clippy --fix --allow-staged
  cargo fmt
  git add -A
  git commit {{FLAGS}}

start-test-environment:
   docker-compose up --wait
   sqlx database create
   sqlx migrate run

open-keycloak-console: start-test-environment
   @echo Use username admin, password admin
   open http://localhost:8080

test: start-test-environment
   cargo test

stop-test-environment:
   docker-compose down

clean-all: stop-test-environment
    cargo clean

install-tools:
    cargo install sqlx-cli --no-default-features --features rustls,postgres
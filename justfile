default:
   just --list

run: start-test-environment
    RUST_LOG=info cargo run

start-test-environment:
   docker-compose up --wait

stop-test-environment:
   docker-compose down

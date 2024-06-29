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

stop-test-environment:
   docker-compose down

clean-all: stop-test-environment
    cargo clean

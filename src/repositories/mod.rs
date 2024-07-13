use crate::repositories::users::UsersRepository;
use sqlx::PgPool;

pub mod users;

pub struct Repositories {
    pub users: UsersRepository,
}

impl Repositories {
    pub fn new(pool: PgPool) -> Self {
        Repositories {
            users: UsersRepository::new(pool),
        }
    }
}

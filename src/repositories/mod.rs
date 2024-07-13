use crate::repositories::users::UsersRepository;
use sqlx::PgPool;

mod users;

pub struct Repositories {
    users: UsersRepository,
}

impl Repositories {
    pub fn new(pool: PgPool) -> Self {
        Repositories {
            users: UsersRepository::new(pool),
        }
    }
}

use crate::repositories::auth_code_flows::AuthCodeFlowsRepository;
use crate::repositories::users::UsersRepository;
use sqlx::PgPool;

pub mod auth_code_flows;
pub mod users;

pub struct Repositories {
    pub auth_code_flow: AuthCodeFlowsRepository,
    pub users: UsersRepository,
}

impl Repositories {
    pub fn new(pool: PgPool) -> Self {
        Repositories {
            auth_code_flow: AuthCodeFlowsRepository::new(pool.clone()),
            users: UsersRepository::new(pool),
        }
    }
}

use sqlx::PgPool;

pub struct UsersRepository {
    pool: PgPool,
}

impl UsersRepository {
    pub fn new(pool: PgPool) -> Self {
        UsersRepository { pool }
    }

    pub async fn create(&self, user: User) -> User {
        sqlx::query!(
            r#"
INSERT INTO users( id, external_id, email, email_verified )
VALUES ( $1, $2, $3, $4 )
RETURNING id
        "#,
            user.id,
            user.external_id,
            user.email,
            user.email_verified
        )
        .fetch_one(&self.pool)
        .await
        .unwrap();

        user
    }

    pub async fn get_user_by_external_id(&self, external_id: &str) -> Option<User> {
        sqlx::query_as!(
            User,
            r#"
            SELECT * FROM users WHERE external_id = $1
            "#,
            external_id
        )
        .fetch_optional(&self.pool)
        .await
        .unwrap()
    }
}

pub struct User {
    pub id: i64,
    pub external_id: Option<String>,
    pub email: String,
    pub email_verified: bool,
}

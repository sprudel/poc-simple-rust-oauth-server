use crate::oauth::primitives::AuthCode;
use chrono::Utc;
use openidconnect::core::CoreResponseType;
use openidconnect::{ClientId, Nonce, PkceCodeChallenge, ResponseTypes, SubjectIdentifier};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgQueryResult;
use sqlx::{Error, PgPool};
use std::time::Duration;
use url::Url;

pub struct AuthCodeFlowsRepository {
    pool: PgPool,
}

impl AuthCodeFlowsRepository {
    pub fn new(pool: PgPool) -> Self {
        Self::spawn_auto_cleanup(pool.clone());
        AuthCodeFlowsRepository { pool }
    }

    fn spawn_auto_cleanup(pool: PgPool) {
        tokio::spawn(async move {
            match sqlx::query!(
                r#"
    DELETE FROM auth_code_flows WHERE expires_at < NOW();
                "#
            )
            .execute(&pool)
            .await
            {
                Ok(_) => {
                    tracing::info!("Successfully cleaned up stale AuthCodeFlows")
                }
                Err(e) => {
                    tracing::error!("Failed to clean up AuthCodeFlows {}", e)
                }
            }
            tokio::time::sleep(Duration::from_secs(60 * 15)).await;
        });
    }

    pub async fn insert(&self, code: &AuthCode, state: AuthCodeState) {
        let flow_data = serde_json::to_value(&state).unwrap();
        sqlx::query!(
            r#"
INSERT INTO auth_code_flows ( code, expires_at, flow_data )
VALUES ( $1, $2, $3 )
            "#,
            code.as_str(),
            state.expires_at,
            flow_data
        )
        .execute(&self.pool)
        .await
        .unwrap();
    }

    pub async fn remove_state(&self, code: &AuthCode) -> Option<AuthCodeState> {
        let state = sqlx::query!(
            r#"
DELETE FROM auth_code_flows
WHERE code = $1
RETURNING flow_data
            "#,
            code.as_str(),
        )
        .fetch_optional(&self.pool)
        .await
        .unwrap();
        state.map(|r| serde_json::from_value(r.flow_data).unwrap())
    }
}

#[derive(Serialize, Deserialize)]
pub struct AuthCodeState {
    pub expires_at: chrono::DateTime<Utc>,
    pub scope: String,
    pub response_type: ResponseTypes<CoreResponseType>,
    pub client_id: ClientId,
    pub nonce: Option<Nonce>,
    pub pkce_code_challenge: Option<PkceCodeChallenge>,
    pub redirect_uri: Url,
    pub subject: SubjectIdentifier,
}

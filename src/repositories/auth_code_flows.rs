use crate::oauth::primitives::AuthCode;
use chrono::Utc;
use openidconnect::core::CoreResponseType;
use openidconnect::{ClientId, Nonce, PkceCodeChallenge, ResponseTypes, SubjectIdentifier};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use url::Url;

pub struct AuthCodeFlowsRepository {
    pool: PgPool,
}

impl AuthCodeFlowsRepository {
    pub fn new(pool: PgPool) -> Self {
        AuthCodeFlowsRepository { pool }
    }

    pub async fn insert(&self, code: &AuthCode, state: AuthCodeState) {
        let flow_data = serde_json::to_value(&state).unwrap();
        sqlx::query!(
            r#"
INSERT INTO auth_code_flows ( code, flow_data )
VALUES ( $1, $2 )
            "#,
            code.as_str(),
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
    pub expiry: chrono::DateTime<Utc>,
    pub scope: String,
    pub response_type: ResponseTypes<CoreResponseType>,
    pub client_id: ClientId,
    pub nonce: Option<Nonce>,
    pub pkce_code_challenge: Option<PkceCodeChallenge>,
    pub redirect_uri: Url,
    pub subject: SubjectIdentifier,
}

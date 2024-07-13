CREATE TABLE users (
    id BIGSERIAL NOT NULL PRIMARY KEY,
    external_id VARCHAR UNIQUE,
    email VARCHAR,
    email_verified BOOLEAN
);

CREATE TABLE users (
    id BIGSERIAL NOT NULL PRIMARY KEY,
    external_id VARCHAR UNIQUE,
    email VARCHAR NOT NULL,
    email_verified BOOLEAN NOT NULL DEFAULT false
);

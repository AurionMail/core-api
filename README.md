psql -h localhost -U aurionuser -d auriondb -f migrations/init.sql

Update from 0.0.6 to 0.0.7
`ALTER TABLE users ADD COLUMN token_version INT NOT NULL DEFAULT 1;`
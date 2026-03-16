ALTER TABLE refresh_tokens ALTER COLUMN ip_address TYPE inet USING ip_address::inet;
ALTER TABLE sessions      ALTER COLUMN ip_address TYPE inet USING ip_address::inet;

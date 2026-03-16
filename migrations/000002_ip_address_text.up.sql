-- Change ip_address columns from inet to text to simplify Go scanning
ALTER TABLE refresh_tokens ALTER COLUMN ip_address TYPE text USING ip_address::text;
ALTER TABLE sessions      ALTER COLUMN ip_address TYPE text USING ip_address::text;

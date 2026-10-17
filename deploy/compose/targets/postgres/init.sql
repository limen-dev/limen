-- Seed for the local PostgreSQL target (docker-entrypoint-initdb.d).
-- Development only. Limen's bootstrap creates the limen_* login roles; this
-- script only provides the dedicated admin login it uses (ADR-0015) and data.
CREATE ROLE limen_admin LOGIN CREATEROLE PASSWORD 'limen-admin-dev-only';
CREATE DATABASE orders OWNER limen_admin;
CREATE DATABASE billing OWNER limen_admin;

\connect orders limen_admin
CREATE TABLE customers (id serial PRIMARY KEY, name text NOT NULL, email text NOT NULL);
CREATE TABLE orders (id serial PRIMARY KEY, customer_id int REFERENCES customers(id), total_cents int NOT NULL);
INSERT INTO customers (name, email) VALUES ('Ada', 'ada@example.com'), ('Grace', 'grace@example.com');
INSERT INTO orders (customer_id, total_cents) VALUES (1, 1250), (1, 990), (2, 4200);

\connect billing limen_admin
CREATE TABLE invoices (id serial PRIMARY KEY, amount_cents int NOT NULL);
INSERT INTO invoices (amount_cents) VALUES (100), (200);

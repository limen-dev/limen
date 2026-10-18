-- Seed for the local MySQL target (docker-entrypoint-initdb.d). Development
-- only. Limen's bootstrap creates the limen_* users; this script provides the
-- dedicated admin it uses (ADR-0015) and data.
CREATE DATABASE orders;
CREATE DATABASE billing;

CREATE USER 'limen_admin'@'%' IDENTIFIED BY 'limen-admin-dev-only';
GRANT CREATE USER ON *.* TO 'limen_admin'@'%';
GRANT ALL PRIVILEGES ON orders.* TO 'limen_admin'@'%' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON billing.* TO 'limen_admin'@'%' WITH GRANT OPTION;

USE orders;
CREATE TABLE customers (id INT AUTO_INCREMENT PRIMARY KEY, name VARCHAR(100) NOT NULL, email VARCHAR(200) NOT NULL);
CREATE TABLE orders (id INT AUTO_INCREMENT PRIMARY KEY, customer_id INT, total_cents INT NOT NULL);
INSERT INTO customers (name, email) VALUES ('Ada', 'ada@example.com'), ('Grace', 'grace@example.com');
INSERT INTO orders (customer_id, total_cents) VALUES (1, 1250), (1, 990), (2, 4200);

USE billing;
CREATE TABLE invoices (id INT AUTO_INCREMENT PRIMARY KEY, amount_cents INT NOT NULL);
INSERT INTO invoices (amount_cents) VALUES (100), (200);

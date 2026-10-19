// Seeds the local MongoDB target (Phase 9): two databases, two Limen-owned
// SCRAM users, and an X.509 user for the worker's client certificate.
// Runs once, on first start, against the temporary server of the image's init.
const orders = db.getSiblingDB("orders");
orders.customers.insertMany([
  { name: "Ada", email: "ada@example.com", tier: "gold" },
  { name: "Grace", email: "grace@example.com", tier: "silver" },
  { name: "Linus", email: "linus@example.com", tier: "silver" },
]);
orders.invoices.insertMany([
  { customer: "Ada", total: 120, card: "4111111111111111" },
  { customer: "Grace", total: 80, card: "5500005555555559" },
]);
db.getSiblingDB("billing").ledger.insertOne({ entry: 1, amount: 500 });

const admin = db.getSiblingDB("admin");
admin.createUser({
  user: "limen-read",
  pwd: "limen-read-dev-only",
  roles: [{ role: "read", db: "orders" }],
});
admin.createUser({
  user: "limen-rw",
  pwd: "limen-rw-dev-only",
  roles: [{ role: "readWrite", db: "orders" }, { role: "read", db: "billing" }],
});
// The worker's certificate subject, in the order MongoDB prints it (RFC 2253).
db.getSiblingDB("$external").runCommand({
  createUser: "CN=limen-x509,O=Limen",
  roles: [{ role: "read", db: "orders" }],
});

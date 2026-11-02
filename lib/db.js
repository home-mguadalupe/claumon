// Shared PostgreSQL pool. Only used when DATABASE_URL is set.
const fs = require('node:fs');
const path = require('node:path');
const { Pool } = require('pg');

let pool;
const getPool = () => (pool ??= new Pool({ connectionString: process.env.DATABASE_URL }));

// db/schema.sql is idempotent, so applying it on every start keeps existing
// databases up to date (docker only runs it when the volume is first created).
async function ensureSchema() {
  await getPool().query(fs.readFileSync(path.join(__dirname, '..', 'db', 'schema.sql'), 'utf8'));
}

const closePool = () => pool?.end();

module.exports = { getPool, ensureSchema, closePool };

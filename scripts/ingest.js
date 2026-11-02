// Usage: DATABASE_URL=postgres://... node scripts/ingest.js backups/*.conf
const { ingestFile, analyze, closePool } = require('../lib/inventory');
const { ensureSchema } = require('../lib/db');

(async () => {
  const files = process.argv.slice(2);
  if (!files.length) {
    console.error('Usage: node scripts/ingest.js <backup.conf>...');
    process.exit(1);
  }
  await ensureSchema();
  let failed = 0;
  for (const f of files) {
    try {
      console.log(f, await ingestFile(f, { analyze: false }));
    } catch (err) {
      failed++;
      console.error(`${f}: ${err.message}`);
    }
  }
  await analyze();
  await closePool();
  process.exit(failed ? 1 : 0);
})();

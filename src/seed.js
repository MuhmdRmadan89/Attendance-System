require('dotenv').config();
const bcrypt = require('bcryptjs');
const { randomUUID } = require('crypto');
const { pool } = require('./db');

async function upsertUser({ id, name, username, password, role }) {
  const hash = await bcrypt.hash(password, 10);
  await pool.query(
    `INSERT INTO employees (id, name, username, password_hash, role, is_active)
     VALUES (?, ?, ?, ?, ?, 1)
     ON DUPLICATE KEY UPDATE
       name=VALUES(name),
       password_hash=VALUES(password_hash),
       role=VALUES(role),
       is_active=1`,
    [id, name, username, hash, role]
  );
}

(async () => {
  try {
    await upsertUser({
      id: '11111111-1111-1111-1111-111111111111',
      name: 'Admin',
      username: 'admin',
      password: '123456',
      role: 'admin'
    });

    await upsertUser({
      id: randomUUID(),
      name: 'Employee One',
      username: 'emp1',
      password: '123456',
      role: 'employee'
    });

    console.log('Seed done ✅');
  } catch (e) {
    console.error('Seed error:', e);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
})();
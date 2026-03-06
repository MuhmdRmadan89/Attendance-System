require('dotenv').config();
const bcrypt = require('bcryptjs');
const { randomUUID } = require('crypto');
const pool = require('./db');

async function upsertUser({ id, name, username, password, role, hourlyRate = 0, baseSalary = 0 }) {
  const hash = await bcrypt.hash(password, 10);
  await pool.query(
    `INSERT INTO employees
      (id, name, username, password_hash, role, hourly_rate, base_salary, is_active)
     VALUES ($1, $2, $3, $4, $5, $6, $7, true)
     ON CONFLICT (username)
     DO UPDATE SET
       name = EXCLUDED.name,
       password_hash = EXCLUDED.password_hash,
       role = EXCLUDED.role,
       hourly_rate = EXCLUDED.hourly_rate,
       base_salary = EXCLUDED.base_salary,
       is_active = true,
       updated_at = NOW()`,
    [id, name, username, hash, role, hourlyRate, baseSalary]
  );
}

(async () => {
  try {
    await upsertUser({
      id: '11111111-1111-1111-1111-111111111111',
      name: 'System Admin',
      username: 'admin',
      password: '123456',
      role: 'admin',
      hourlyRate: 0,
      baseSalary: 0,
    });

    await upsertUser({
      id: randomUUID(),
      name: 'Employee One',
      username: 'emp1',
      password: '123456',
      role: 'employee',
      hourlyRate: 50,
      baseSalary: 3000,
    });

    console.log('Seed completed successfully.');
  } catch (error) {
    console.error('Seed failed:', error.message);
    process.exitCode = 1;
  } finally {
    await pool.end();
  }
})();

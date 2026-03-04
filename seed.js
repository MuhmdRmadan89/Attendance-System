require('dotenv').config();
const bcrypt = require('bcryptjs');
const pool = require('./src/db');

(async ()=>{
  const hash = await bcrypt.hash('123456', 10);

  await pool.query(
    `INSERT INTO employees (name, username, password_hash, role)
     VALUES ($1,$2,$3,$4)`,
    ['Admin','admin',hash,'admin']
  );

  await pool.query(
    `INSERT INTO employees (name, username, password_hash, role)
     VALUES ($1,$2,$3,$4)`,
    ['Employee 1','emp1',hash,'employee']
  );

  console.log("Seed Done");
  process.exit();
})();
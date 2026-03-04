require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomUUID } = require('crypto');
const pool = require('./db');

const app = express();

app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// ================== HELPERS ==================

function todayStr(){
  return new Date().toISOString().slice(0,10);
}

function makeToken(user){
  return jwt.sign(
    { id:user.id, role:user.role, username:user.username },
    process.env.JWT_SECRET,
    { expiresIn:'7d' }
  );
}

// ================== AUTH MIDDLEWARE ==================

function authEmployee(req, res, next) {
  try {
    const header = req.headers.authorization;

    if (!header)
      return res.status(401).json({ error: 'Unauthorized' });

    const token = header.split(' ')[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    req.user = decoded;
    next();

  } catch (err) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

// ================== LOGIN ==================

app.post('/api/auth/login', async (req,res)=>{
  try {
    const { username, password, deviceId } = req.body;

    const { rows } = await pool.query(
      'SELECT * FROM employees WHERE username=$1 AND is_active=true',
      [username]
    );

    if(!rows.length)
      return res.status(401).json({error:'Invalid credentials'});

    const user = rows[0];

    const ok = await bcrypt.compare(password, user.password_hash);
    if(!ok)
      return res.status(401).json({error:'Invalid credentials'});

    // Device binding (اختياري)
    if(user.role !== 'admin' && process.env.DEVICE_BINDING_ENABLED === '1'){

      if(user.device_id && user.device_id !== deviceId)
        return res.status(403).json({error:'Account locked to another device'});

      if(!user.device_id)
        await pool.query(
          'UPDATE employees SET device_id=$1 WHERE id=$2',
          [deviceId, user.id]
        );
    }

    res.json({
      accessToken: makeToken(user),
      user:{
        id:user.id,
        role:user.role,
        username:user.username,
        name:user.name
      }
    });

  } catch(err){
    console.error(err);
    res.status(500).json({error:'Server error'});
  }
});

// ================== TODAY STATUS ==================

app.get('/api/employee/today', authEmployee, async (req,res)=>{
  try{
    const employeeId = req.user.id;
    const date = todayStr();

    const { rows } = await pool.query(
      `SELECT * FROM attendance_days
       WHERE employee_id=$1 AND work_date=$2`,
      [employeeId, date]
    );

    const day = rows[0] || null;

    res.json({
      date,
      day,
      canCheckIn: !day || !day.check_in_time,
      canCheckOut: day && day.check_in_time && !day.check_out_time
    });

  } catch(err){
    console.error(err);
    res.status(500).json({error:'Server error'});
  }
});

// ================== CHECK IN ==================

app.post('/api/employee/checkin', authEmployee, async (req,res)=>{
  try{
    const employeeId = req.user.id;
    const date = todayStr();

    // منع تكرار تسجيل الحضور
    const { rows } = await pool.query(
      `SELECT * FROM attendance_days
       WHERE employee_id=$1 AND work_date=$2`,
      [employeeId, date]
    );

    if(rows.length && rows[0].check_in_time)
      return res.status(400).json({error:'Already checked in'});

    await pool.query(
      `INSERT INTO attendance_days
       (id, employee_id, work_date, check_in_time)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (employee_id, work_date)
       DO UPDATE SET check_in_time=$4`,
      [randomUUID(), employeeId, date, new Date()]
    );

    res.json({status:'IN'});

  } catch(err){
    console.error(err);
    res.status(500).json({error:'Server error'});
  }
});

// ================== CHECK OUT ==================

app.post('/api/employee/checkout', authEmployee, async (req,res)=>{
  try{
    const employeeId = req.user.id;
    const date = todayStr();

    const { rows } = await pool.query(
      `SELECT * FROM attendance_days
       WHERE employee_id=$1 AND work_date=$2`,
      [employeeId, date]
    );

    if(!rows.length || !rows[0].check_in_time)
      return res.status(400).json({error:'Must check in first'});

    if(rows[0].check_out_time)
      return res.status(400).json({error:'Already checked out'});

    await pool.query(
      `UPDATE attendance_days
       SET check_out_time=$1
       WHERE employee_id=$2 AND work_date=$3`,
      [new Date(), employeeId, date]
    );

    res.json({status:'OUT'});

  } catch(err){
    console.error(err);
    res.status(500).json({error:'Server error'});
  }
});

// ================== TEST ==================

app.get('/test', (req,res)=>{
  res.send("Server works");
});

// ================== START ==================

app.listen(process.env.PORT, ()=>{
  console.log('Server running on port '+process.env.PORT);
});
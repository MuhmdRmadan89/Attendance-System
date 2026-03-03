require('dotenv').config();

const path = require('path');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const ExcelJS = require('exceljs');
const { randomUUID } = require('crypto');

const { pool } = require('./db');
const { authRequired, requireRole } = require('./auth');
const { distanceMeters, isFiniteNumber } = require('./security');

const app = express();
app.use(express.json({ limit: '1mb' }));
app.use(express.static(path.join(__dirname, '..', 'public')));

// Redirect / -> employee login
app.get('/', (req, res) => res.redirect('/employee/login.html'));

function todayDate() {
  return new Date().toISOString().slice(0, 10);
}

function makeToken(userRow) {
  return jwt.sign(
    { id: userRow.id, role: userRow.role, username: userRow.username, name: userRow.name },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
}

function geoCheck({ latitude, longitude, accuracyM }) {
  const officeLat = Number(process.env.OFFICE_LAT);
  const officeLng = Number(process.env.OFFICE_LNG);
  const radius = Number(process.env.OFFICE_RADIUS_METERS);
  const maxAcc = Number(process.env.MAX_GPS_ACCURACY_METERS);

  const hasLoc = isFiniteNumber(latitude) && isFiniteNumber(longitude);
  const accOk = isFiniteNumber(accuracyM) ? accuracyM <= maxAcc : false;

  let dist = null;
  let inside = false;

  if (hasLoc) {
    dist = distanceMeters(officeLat, officeLng, latitude, longitude);
    inside = dist <= radius;
  }

  // حالة التسجيل
  // - لو accuracy ضعيف: WEAK_GPS
  // - لو مفيش لوكيشن: NO_GPS
  // - لو داخل: OK
  let status = 'OK';
  if (!hasLoc) status = 'NO_GPS';
  else if (!accOk) status = 'WEAK_GPS';

  return { hasLoc, accOk, dist, inside, status };
}

// ============== AUTH ==============
app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, deviceId } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username & password required' });

    const [rows] = await pool.query(
      `SELECT id, name, username, password_hash, role, is_active, device_id
       FROM employees WHERE username=? LIMIT 1`,
      [username]
    );

    if (!rows.length) return res.status(401).json({ error: 'Invalid credentials' });
    const user = rows[0];
    if (!user.is_active) return res.status(403).json({ error: 'User inactive' });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    // Device Binding (على الموظفين فقط)
    const deviceBindingEnabled = String(process.env.DEVICE_BINDING_ENABLED || '1') === '1';
    if (deviceBindingEnabled && user.role === 'employee') {
      if (!deviceId) return res.status(400).json({ error: 'Missing deviceId' });

      if (user.device_id && user.device_id !== deviceId) {
        return res.status(403).json({ error: 'Account locked to another device' });
      }
      if (!user.device_id) {
        await pool.query(`UPDATE employees SET device_id=? WHERE id=?`, [deviceId, user.id]);
      }
    }

    const accessToken = makeToken(user);
    res.json({
      accessToken,
      user: { id: user.id, role: user.role, username: user.username, name: user.name }
    });
  } catch (e) {
    console.error('LOGIN ERROR:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/me', authRequired, (req, res) => {
  res.json({ user: req.user });
});

// ============== EMPLOYEE ==============
app.get('/api/employee/today', authRequired, async (req, res) => {
  try {
    if (req.user.role !== 'employee') return res.status(403).json({ error: 'Forbidden' });

    const d = todayDate();
    const [rows] = await pool.query(
      `SELECT * FROM attendance_days WHERE employee_id=? AND work_date=? LIMIT 1`,
      [req.user.id, d]
    );

    const day = rows[0] || null;

    res.json({
      date: d,
      day,
      canCheckIn: !day?.check_in_time,
      canCheckOut: !!day?.check_in_time && !day?.check_out_time
    });
  } catch (e) {
    console.error('TODAY ERROR:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/employee/checkin', authRequired, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    if (req.user.role !== 'employee') return res.status(403).json({ error: 'Forbidden' });

    const { latitude, longitude, accuracyM, deviceId } = req.body || {};
    const d = todayDate();

    // Device binding check (لضمان نفس الجهاز حتى بعد تسجيل الدخول)
    const deviceBindingEnabled = String(process.env.DEVICE_BINDING_ENABLED || '1') === '1';
    if (deviceBindingEnabled) {
      const [urows] = await conn.query(`SELECT device_id FROM employees WHERE id=? LIMIT 1`, [req.user.id]);
      const saved = urows[0]?.device_id || null;
      if (saved && deviceId && saved !== deviceId) {
        return res.status(403).json({ error: 'Account locked to another device' });
      }
    }

    const geo = geoCheck({ latitude, longitude, accuracyM });

    // لازم يكون داخل النطاق (حتى لو accuracy ضعيف هنسمح لكن نسجل WEAK_GPS)
    if (!geo.inside) {
      await conn.query(
        `INSERT INTO attendance_events
         (id, employee_id, event_type, event_time, work_date, lat, lng, accuracy_m, distance_m, inside_geofence, device_id, user_agent, ip_address, result_status)
         VALUES (?, ?, 'IN', NOW(), ?, ?, ?, ?, ?, 0, ?, ?, ?, 'OUTSIDE_RANGE')`,
        [
          randomUUID(), req.user.id, d,
          geo.hasLoc ? latitude : null, geo.hasLoc ? longitude : null,
          isFiniteNumber(accuracyM) ? accuracyM : null,
          geo.dist, deviceId || null,
          String(req.headers['user-agent'] || '').slice(0,255),
          String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').slice(0,64)
        ]
      );
      return res.status(400).json({ error: 'Outside office range' });
    }

    await conn.beginTransaction();

    // lock row
    const [existing] = await conn.query(
      `SELECT id, check_in_time FROM attendance_days WHERE employee_id=? AND work_date=? FOR UPDATE`,
      [req.user.id, d]
    );

    if (existing.length && existing[0].check_in_time) {
      await conn.rollback();
      return res.status(400).json({ error: 'Already checked in' });
    }

    const status = geo.status; // OK / WEAK_GPS / NO_GPS (بس NO_GPS غالبًا مش هيبقى inside)

    if (!existing.length) {
      await conn.query(
        `INSERT INTO attendance_days
         (id, employee_id, work_date, check_in_time, check_in_lat, check_in_lng, check_in_accuracy_m, check_in_distance_m, check_in_status)
         VALUES (?, ?, ?, NOW(), ?, ?, ?, ?, ?)`,
        [
          randomUUID(), req.user.id, d,
          geo.hasLoc ? latitude : null,
          geo.hasLoc ? longitude : null,
          isFiniteNumber(accuracyM) ? accuracyM : null,
          geo.dist,
          status
        ]
      );
    } else {
      await conn.query(
        `UPDATE attendance_days
         SET check_in_time=NOW(), check_in_lat=?, check_in_lng=?, check_in_accuracy_m=?, check_in_distance_m=?, check_in_status=?
         WHERE id=?`,
        [
          geo.hasLoc ? latitude : null,
          geo.hasLoc ? longitude : null,
          isFiniteNumber(accuracyM) ? accuracyM : null,
          geo.dist,
          status,
          existing[0].id
        ]
      );
    }

    await conn.query(
      `INSERT INTO attendance_events
       (id, employee_id, event_type, event_time, work_date, lat, lng, accuracy_m, distance_m, inside_geofence, device_id, user_agent, ip_address, result_status)
       VALUES (?, ?, 'IN', NOW(), ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
      [
        randomUUID(), req.user.id, d,
        geo.hasLoc ? latitude : null, geo.hasLoc ? longitude : null,
        isFiniteNumber(accuracyM) ? accuracyM : null,
        geo.dist, deviceId || null,
        String(req.headers['user-agent'] || '').slice(0,255),
        String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').slice(0,64),
        status
      ]
    );

    await conn.commit();
    res.json({ ok: true, status });
  } catch (e) {
    try { await conn.rollback(); } catch {}
    console.error('CHECKIN ERROR:', e);
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

app.post('/api/employee/checkout', authRequired, async (req, res) => {
  const conn = await pool.getConnection();
  try {
    if (req.user.role !== 'employee') return res.status(403).json({ error: 'Forbidden' });

    const { latitude, longitude, accuracyM, deviceId } = req.body || {};
    const d = todayDate();

    const geo = geoCheck({ latitude, longitude, accuracyM });

    // لازم داخل النطاق
    if (!geo.inside) {
      await conn.query(
        `INSERT INTO attendance_events
         (id, employee_id, event_type, event_time, work_date, lat, lng, accuracy_m, distance_m, inside_geofence, device_id, user_agent, ip_address, result_status)
         VALUES (?, ?, 'OUT', NOW(), ?, ?, ?, ?, ?, 0, ?, ?, ?, 'OUTSIDE_RANGE')`,
        [
          randomUUID(), req.user.id, d,
          geo.hasLoc ? latitude : null, geo.hasLoc ? longitude : null,
          isFiniteNumber(accuracyM) ? accuracyM : null,
          geo.dist, deviceId || null,
          String(req.headers['user-agent'] || '').slice(0,255),
          String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').slice(0,64)
        ]
      );
      return res.status(400).json({ error: 'Outside office range' });
    }

    await conn.beginTransaction();

    const [rows] = await conn.query(
      `SELECT id, check_in_time, check_out_time FROM attendance_days WHERE employee_id=? AND work_date=? FOR UPDATE`,
      [req.user.id, d]
    );

    if (!rows.length || !rows[0].check_in_time) {
      await conn.rollback();
      return res.status(400).json({ error: 'No check-in found for today' });
    }

    if (rows[0].check_out_time) {
      await conn.rollback();
      return res.status(400).json({ error: 'Already checked out' });
    }

    const status = geo.status;

    await conn.query(
      `UPDATE attendance_days
       SET check_out_time=NOW(), check_out_lat=?, check_out_lng=?, check_out_accuracy_m=?, check_out_distance_m=?, check_out_status=?
       WHERE id=?`,
      [
        geo.hasLoc ? latitude : null,
        geo.hasLoc ? longitude : null,
        isFiniteNumber(accuracyM) ? accuracyM : null,
        geo.dist,
        status,
        rows[0].id
      ]
    );

    await conn.query(
      `INSERT INTO attendance_events
       (id, employee_id, event_type, event_time, work_date, lat, lng, accuracy_m, distance_m, inside_geofence, device_id, user_agent, ip_address, result_status)
       VALUES (?, ?, 'OUT', NOW(), ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)`,
      [
        randomUUID(), req.user.id, d,
        geo.hasLoc ? latitude : null, geo.hasLoc ? longitude : null,
        isFiniteNumber(accuracyM) ? accuracyM : null,
        geo.dist, deviceId || null,
        String(req.headers['user-agent'] || '').slice(0,255),
        String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').slice(0,64),
        status
      ]
    );

    await conn.commit();
    res.json({ ok: true, status });
  } catch (e) {
    try { await conn.rollback(); } catch {}
    console.error('CHECKOUT ERROR:', e);
    res.status(500).json({ error: 'Server error' });
  } finally {
    conn.release();
  }
});

// ============== ADMIN ==============
app.get('/api/admin/employees', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const [rows] = await pool.query(
      `SELECT id, name, username, role, is_active, device_id, created_at
       FROM employees
       WHERE role='employee'
       ORDER BY created_at DESC`
    );
    res.json({ rows });
  } catch (e) {
    console.error('ADMIN EMP LIST ERROR:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/employees', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const { name, username, password } = req.body || {};
    if (!name || !username || !password) return res.status(400).json({ error: 'name, username, password required' });

    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      `INSERT INTO employees (id, name, username, password_hash, role, is_active)
       VALUES (?, ?, ?, ?, 'employee', 1)`,
      [randomUUID(), name, username, hash]
    );
    res.json({ ok: true });
  } catch (e) {
    console.error('ADMIN EMP CREATE ERROR:', e);
    if (String(e?.code) === 'ER_DUP_ENTRY') return res.status(400).json({ error: 'Username already exists' });
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/employees/:id/toggle', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const id = req.params.id;
    await pool.query(`UPDATE employees SET is_active = IF(is_active=1,0,1) WHERE id=? AND role='employee'`, [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('ADMIN EMP TOGGLE ERROR:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/employees/:id/reset-device', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const id = req.params.id;
    await pool.query(`UPDATE employees SET device_id=NULL WHERE id=? AND role='employee'`, [id]);
    res.json({ ok: true });
  } catch (e) {
    console.error('ADMIN RESET DEVICE ERROR:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/attendance', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const date = req.query.date;
    if (!date) return res.status(400).json({ error: 'date required' });

    const [rows] = await pool.query(
      `SELECT e.name, e.username, d.work_date, d.check_in_time, d.check_out_time,
              d.check_in_distance_m, d.check_in_status,
              d.check_out_distance_m, d.check_out_status
       FROM employees e
       LEFT JOIN attendance_days d ON d.employee_id=e.id AND d.work_date=?
       WHERE e.role='employee'
       ORDER BY e.name ASC`,
      [date]
    );
    res.json({ rows });
  } catch (e) {
    console.error('ADMIN ATT ERROR:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/export', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const { from, to } = req.query;
    if (!from || !to) return res.status(400).json({ error: 'from & to required' });

    const [rows] = await pool.query(
      `SELECT e.name, e.username, d.work_date, d.check_in_time, d.check_out_time,
              d.check_in_distance_m, d.check_in_status, d.check_out_distance_m, d.check_out_status
       FROM attendance_days d
       JOIN employees e ON e.id=d.employee_id
       WHERE d.work_date BETWEEN ? AND ?
       ORDER BY d.work_date ASC, e.name ASC`,
      [from, to]
    );

    const wb = new ExcelJS.Workbook();
    const ws = wb.addWorksheet('Attendance');

    ws.columns = [
      { header: 'Date', key: 'work_date', width: 12 },
      { header: 'Name', key: 'name', width: 22 },
      { header: 'Username', key: 'username', width: 16 },
      { header: 'Check In', key: 'check_in_time', width: 22 },
      { header: 'Check Out', key: 'check_out_time', width: 22 },
      { header: 'In Distance(m)', key: 'check_in_distance_m', width: 14 },
      { header: 'In Status', key: 'check_in_status', width: 14 },
      { header: 'Out Distance(m)', key: 'check_out_distance_m', width: 14 },
      { header: 'Out Status', key: 'check_out_status', width: 14 }
    ];

    rows.forEach(r => ws.addRow(r));

    const buf = await wb.xlsx.writeBuffer();
    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="attendance_${from}_to_${to}.xlsx"`);
    res.send(Buffer.from(buf));
  } catch (e) {
    console.error('EXPORT ERROR:', e);
    res.status(500).json({ error: 'Server error' });
  }
});

// health
app.get('/health', (req, res) => res.json({ ok: true }));

const port = Number(process.env.PORT || 3001);
app.listen(port, () => console.log(`Server running: http://localhost:${port}`));
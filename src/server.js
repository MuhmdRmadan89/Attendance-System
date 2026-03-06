
require('dotenv').config();
const express = require('express');
const path = require('path');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { randomUUID } = require('crypto');
const ExcelJS = require('exceljs');
const {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} = require('@simplewebauthn/server');

const pool = require('./db');
const { distanceMeters, isFiniteNumber } = require('./security');

const app = express();
app.use(express.json({ limit: '1mb' }));

const PORT = Number(process.env.PORT || 3000);
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret';
const OFFICE_LAT = Number(process.env.OFFICE_LAT || 31.2001);
const OFFICE_LNG = Number(process.env.OFFICE_LNG || 29.9187);
const OFFICE_RADIUS_METERS = Number(process.env.OFFICE_RADIUS_METERS || 50);
const MAX_GPS_ACCURACY_METERS = Number(process.env.MAX_GPS_ACCURACY_METERS || 100);
const DEVICE_BINDING_ENABLED = process.env.DEVICE_BINDING_ENABLED === '1';
const DEVICE_BINDING_STRICT = process.env.DEVICE_BINDING_STRICT === '1';
const GEOFENCE_ENFORCED = process.env.GEOFENCE_ENFORCED !== '0';
const WEBAUTHN_RP_NAME = process.env.WEBAUTHN_RP_NAME || 'Injaz HR';
const WEBAUTHN_ORIGIN = process.env.WEBAUTHN_ORIGIN || `http://localhost:${PORT}`;
const WEBAUTHN_RP_ID = process.env.WEBAUTHN_RP_ID || new URL(WEBAUTHN_ORIGIN).hostname;

let attendanceModeCache = null;
const tableExistsCache = new Map();
const columnsCache = new Map();
const webauthnChallengeStore = new Map();

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

function monthOrCurrent(monthInput) {
  if (typeof monthInput === 'string' && /^\d{4}-\d{2}$/.test(monthInput)) return monthInput;
  const d = new Date();
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}`;
}

function asMoney(value) {
  return Number((Number(value || 0)).toFixed(2));
}

function toBase64URL(input) {
  return Buffer.from(input).toString('base64url');
}

function fromBase64URL(input) {
  return Buffer.from(String(input || ''), 'base64url');
}

function makeToken(user) {
  return jwt.sign(
    { id: user.id, role: user.role, username: user.username, name: user.name },
    JWT_SECRET,
    { expiresIn: '7d' }
  );
}

function authRequired(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Unauthorized' });

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: 'Unauthorized' });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (req.user.role !== role) return res.status(403).json({ error: 'Forbidden' });
    return next();
  };
}

async function tableExists(tableName) {
  if (tableExistsCache.has(tableName)) return tableExistsCache.get(tableName);
  const { rows } = await pool.query('SELECT to_regclass($1) AS x', [`public.${tableName}`]);
  const ok = !!rows[0]?.x;
  tableExistsCache.set(tableName, ok);
  return ok;
}

async function getTableColumns(tableName) {
  if (columnsCache.has(tableName)) return columnsCache.get(tableName);
  const { rows } = await pool.query(
    `SELECT column_name
     FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1`,
    [tableName]
  );
  const set = new Set(rows.map((r) => r.column_name));
  columnsCache.set(tableName, set);
  return set;
}

async function employeeHasColumn(col) {
  const cols = await getTableColumns('employees');
  return cols.has(col);
}

async function getAttendanceMode() {
  if (attendanceModeCache) return attendanceModeCache;
  if (await tableExists('attendance')) attendanceModeCache = 'attendance';
  else if (await tableExists('attendance_days')) attendanceModeCache = 'attendance_days';
  else attendanceModeCache = null;
  return attendanceModeCache;
}

function validateLocation(body) {
  const { lat, lng, accuracy } = body || {};
  if (!isFiniteNumber(lat) || !isFiniteNumber(lng)) {
    return { ok: false, error: 'Invalid GPS coordinates' };
  }

  const acc = isFiniteNumber(accuracy) ? accuracy : null;
  const distance = distanceMeters(lat, lng, OFFICE_LAT, OFFICE_LNG);

  if (GEOFENCE_ENFORCED && distance > OFFICE_RADIUS_METERS) {
    return { ok: false, error: `Outside office geofence (${Math.round(distance)}m)` };
  }

  if (GEOFENCE_ENFORCED && acc !== null && acc > MAX_GPS_ACCURACY_METERS) {
    return { ok: false, error: `Low GPS accuracy (${Math.round(acc)}m)` };
  }

  return {
    ok: true,
    loc: {
      lat,
      lng,
      accuracy: acc,
      distance: Math.round(distance),
      capturedAt: new Date().toISOString(),
    },
  };
}

function parseLocDistance(value) {
  if (!value) return null;
  if (typeof value === 'object') {
    const d = Number(value.distance);
    return Number.isFinite(d) ? d : null;
  }
  if (typeof value === 'string') {
    try {
      const obj = JSON.parse(value);
      const d = Number(obj.distance);
      return Number.isFinite(d) ? d : null;
    } catch {
      return null;
    }
  }
  return null;
}

function parseStoredCredential(raw) {
  if (!raw) return null;
  const x = typeof raw === 'string'
    ? (() => { try { return JSON.parse(raw); } catch { return null; } })()
    : raw;

  if (!x || !x.id || !x.publicKey) return null;

  return {
    id: String(x.id),
    publicKey: String(x.publicKey),
    counter: Number(x.counter || 0),
    transports: Array.isArray(x.transports) ? x.transports : [],
  };
}

function storeChallenge(key, challenge, metadata = {}) {
  webauthnChallengeStore.set(key, {
    challenge,
    metadata,
    expiresAt: Date.now() + 5 * 60 * 1000,
  });
}

function consumeChallenge(key) {
  const x = webauthnChallengeStore.get(key);
  webauthnChallengeStore.delete(key);
  if (!x) return null;
  if (Date.now() > x.expiresAt) return null;
  return x;
}

async function upsertDeviceBinding(user, deviceId, cols) {
  if (!DEVICE_BINDING_ENABLED || user.role === 'admin' || !cols.has('device_id')) return { ok: true };
  if (!deviceId) return { ok: false, status: 400, error: 'deviceId is required' };

  if (user.device_id && user.device_id !== deviceId) {
    if (DEVICE_BINDING_STRICT) return { ok: false, status: 403, error: 'Account is bound to another device' };
    await pool.query('UPDATE employees SET device_id = $1 WHERE id = $2', [deviceId, user.id]);
    return { ok: true };
  }

  if (!user.device_id) {
    await pool.query('UPDATE employees SET device_id = $1 WHERE id = $2', [deviceId, user.id]);
  }

  return { ok: true };
}

async function getEmployeeForAuthByUsername(username) {
  const cols = await getTableColumns('employees');
  const pick = ['id', 'name', 'username', 'password_hash'];
  ['role', 'device_id', 'is_active', 'webauthn_credential'].forEach((x) => {
    if (cols.has(x)) pick.push(x);
  });

  const { rows } = await pool.query(`SELECT ${pick.join(', ')} FROM employees WHERE username = $1`, [username]);
  const row = rows[0] || null;
  if (!row) return null;

  return {
    ...row,
    role: row.role || 'employee',
    is_active: row.is_active == null ? true : !!row.is_active,
  };
}

async function getEmployeeForAuthById(id) {
  const cols = await getTableColumns('employees');
  const pick = ['id', 'name', 'username'];
  ['role', 'device_id', 'is_active', 'webauthn_credential'].forEach((x) => {
    if (cols.has(x)) pick.push(x);
  });

  const { rows } = await pool.query(`SELECT ${pick.join(', ')} FROM employees WHERE id = $1`, [id]);
  const row = rows[0] || null;
  if (!row) return null;

  return {
    ...row,
    role: row.role || 'employee',
    is_active: row.is_active == null ? true : !!row.is_active,
  };
}

function computeDayMetrics(day, employee) {
  if (!day.check_in || !day.check_out) return { workedMinutes: 0, lateMinutes: 0, lateDeduction: 0 };

  const inTime = new Date(day.check_in);
  const outTime = new Date(day.check_out);
  let workedMinutes = Math.max(0, Math.round((outTime - inTime) / 60000));
  workedMinutes = Math.max(0, workedMinutes - Number(employee.break_minutes || 0));

  const [h, m] = String(employee.scheduled_start || '09:00').split(':').map((x) => Number(x));
  const start = new Date(inTime);
  start.setHours(h || 9, m || 0, 0, 0);

  const lateMinutes = Math.max(0, Math.round((inTime - start) / 60000));
  const lateDeduction = (lateMinutes / 60) * Number(employee.hourly_rate || 0);

  return { workedMinutes, lateMinutes, lateDeduction };
}

async function loadAttendanceInMonth(employeeId, month) {
  const mode = await getAttendanceMode();
  if (!mode) return [];
  const from = `${month}-01`;

  if (mode === 'attendance') {
    const { rows } = await pool.query(
      `SELECT id, employee_id, date, check_in, check_out, loc_in, loc_out
       FROM attendance
       WHERE employee_id = $1
         AND date >= CAST($2 AS DATE)
         AND date < (CAST($2 AS DATE) + INTERVAL '1 month')
       ORDER BY date ASC`,
      [employeeId, from]
    );
    return rows;
  }

  const { rows } = await pool.query(
    `SELECT id, employee_id, work_date AS date, check_in_time AS check_in, check_out_time AS check_out,
            NULL AS loc_in, NULL AS loc_out
     FROM attendance_days
     WHERE employee_id = $1
       AND work_date >= CAST($2 AS DATE)
       AND work_date < (CAST($2 AS DATE) + INTERVAL '1 month')
     ORDER BY work_date ASC`,
    [employeeId, from]
  );
  return rows;
}

async function loadFinancialsInMonth(employeeId, month) {
  if (!(await tableExists('financials'))) return [];

  const from = `${month}-01`;
  const { rows } = await pool.query(
    `SELECT id, employee_id, type, amount, reason, date
     FROM financials
     WHERE employee_id = $1
       AND date >= CAST($2 AS DATE)
       AND date < (CAST($2 AS DATE) + INTERVAL '1 month')
     ORDER BY date DESC`,
    [employeeId, from]
  );
  return rows;
}

function buildPayrollSummary(employee, attendanceRows, financialRows, month) {
  let workedMinutes = 0;
  let lateMinutes = 0;
  let lateDeduction = 0;

  const attendance = attendanceRows.map((d) => {
    const metrics = computeDayMetrics(d, employee);
    workedMinutes += metrics.workedMinutes;
    lateMinutes += metrics.lateMinutes;
    lateDeduction += metrics.lateDeduction;

    return {
      date: d.date,
      checkIn: d.check_in,
      checkOut: d.check_out,
      workedHours: Number((metrics.workedMinutes / 60).toFixed(2)),
      lateMinutes: metrics.lateMinutes,
    };
  });

  let bonuses = 0;
  let manualDeductions = 0;
  for (const f of financialRows) {
    if (f.type === 'bonus') bonuses += Number(f.amount || 0);
    if (f.type === 'deduction') manualDeductions += Number(f.amount || 0);
  }

  const workedHours = workedMinutes / 60;
  const hourlyRate = Number(employee.hourly_rate || 0);
  const baseSalary = Number(employee.base_salary || 0);
  const hoursValue = workedHours * hourlyRate;
  const deductions = manualDeductions + lateDeduction;
  const gross = baseSalary + hoursValue + bonuses;
  const net = gross - deductions;

  return {
    month,
    employee: {
      id: employee.id,
      name: employee.name,
      username: employee.username,
      hourlyRate,
      baseSalary,
      scheduledStart: employee.scheduled_start || '09:00',
      breakMinutes: Number(employee.break_minutes || 60),
    },
    totals: {
      daysWorked: attendance.filter((x) => x.checkIn && x.checkOut).length,
      workedHours: Number(workedHours.toFixed(2)),
      lateMinutes,
      lateDeduction: asMoney(lateDeduction),
      bonuses: asMoney(bonuses),
      manualDeductions: asMoney(manualDeductions),
      baseSalary: asMoney(baseSalary),
      hoursValue: asMoney(hoursValue),
      gross: asMoney(gross),
      net: asMoney(net),
    },
    financials: financialRows,
    attendance,
  };
}

async function getEmployeeById(id) {
  const cols = await getTableColumns('employees');
  const pick = ['id', 'name', 'username'];
  ['hourly_rate', 'base_salary', 'scheduled_start', 'break_minutes'].forEach((c) => {
    if (cols.has(c)) pick.push(c);
  });

  const { rows } = await pool.query(`SELECT ${pick.join(', ')} FROM employees WHERE id = $1`, [id]);
  const r = rows[0] || null;
  if (!r) return null;

  return {
    ...r,
    hourly_rate: r.hourly_rate ?? 0,
    base_salary: r.base_salary ?? 0,
    scheduled_start: r.scheduled_start ?? '09:00',
    break_minutes: r.break_minutes ?? 60,
  };
}

async function getAllEmployees() {
  const cols = await getTableColumns('employees');
  const pick = ['id', 'name', 'username', 'password_hash'];
  [
    'role',
    'device_id',
    'is_active',
    'hourly_rate',
    'base_salary',
    'scheduled_start',
    'break_minutes',
    'created_at',
  ].forEach((c) => {
    if (cols.has(c)) pick.push(c);
  });

  const orderBy = cols.has('created_at') ? 'created_at DESC NULLS LAST, name ASC' : 'name ASC';
  const { rows } = await pool.query(`SELECT ${pick.join(', ')} FROM employees ORDER BY ${orderBy}`);

  return rows.map((r) => ({
    ...r,
    role: r.role || 'employee',
    is_active: r.is_active == null ? true : !!r.is_active,
    hourly_rate: Number(r.hourly_rate || 0),
    base_salary: Number(r.base_salary || 0),
    scheduled_start: r.scheduled_start || '09:00',
    break_minutes: Number(r.break_minutes || 60),
  }));
}

async function performAttendanceAction(employeeId, action, locBody) {
  const v = validateLocation(locBody || {});
  if (!v.ok) return { status: 400, body: { error: v.error } };

  const date = todayStr();
  const t = new Date();
  const mode = await getAttendanceMode();
  if (!mode) return { status: 500, body: { error: 'No attendance table found. Run SQL migration first.' } };

  if (action === 'checkin') {
    if (mode === 'attendance') {
      await pool.query(
        `INSERT INTO attendance (id, employee_id, date, check_in, loc_in)
         VALUES ($1, $2, CAST($3 AS DATE), $4, $5)
         ON CONFLICT (employee_id, date)
         DO UPDATE SET
           check_in = COALESCE(attendance.check_in, EXCLUDED.check_in),
           loc_in = COALESCE(attendance.loc_in, EXCLUDED.loc_in),
           updated_at = NOW()`,
        [randomUUID(), employeeId, date, t, JSON.stringify(v.loc)]
      );
    } else {
      await pool.query(
        `INSERT INTO attendance_days (id, employee_id, work_date, check_in_time)
         VALUES ($1, $2, CAST($3 AS DATE), $4)
         ON CONFLICT (employee_id, work_date)
         DO UPDATE SET
           check_in_time = COALESCE(attendance_days.check_in_time, EXCLUDED.check_in_time)`,
        [randomUUID(), employeeId, date, t]
      );
    }
    return { status: 200, body: { success: true, distance: v.loc.distance } };
  }

  if (action === 'checkout') {
    const { rows } = mode === 'attendance'
      ? await pool.query(
        `UPDATE attendance
         SET check_out = $1, loc_out = $2, updated_at = NOW()
         WHERE employee_id = $3
           AND date = CAST($4 AS DATE)
           AND check_in IS NOT NULL
         RETURNING id`,
        [t, JSON.stringify(v.loc), employeeId, date]
      )
      : await pool.query(
        `UPDATE attendance_days
         SET check_out_time = $1
         WHERE employee_id = $2
           AND work_date = CAST($3 AS DATE)
           AND check_in_time IS NOT NULL
         RETURNING id`,
        [t, employeeId, date]
      );

    if (!rows.length) return { status: 400, body: { error: 'Check-in required before check-out' } };
    return { status: 200, body: { success: true, distance: v.loc.distance } };
  }

  return { status: 400, body: { error: 'Invalid attendance action' } };
}

app.post('/api/auth/login', async (req, res) => {
  try {
    const { username, password, deviceId } = req.body || {};
    if (!username || !password) return res.status(400).json({ error: 'username and password are required' });

    const user = await getEmployeeForAuthByUsername(username);
    if (!user || !user.is_active) return res.status(401).json({ error: 'Invalid credentials' });

    const ok = await bcrypt.compare(password, user.password_hash || '');
    if (!ok) return res.status(401).json({ error: 'Invalid credentials' });

    const cols = await getTableColumns('employees');
    const bind = await upsertDeviceBinding(user, deviceId, cols);
    if (!bind.ok) return res.status(bind.status).json({ error: bind.error });

    return res.json({
      accessToken: makeToken(user),
      user: { id: user.id, name: user.name, username: user.username, role: user.role },
    });
  } catch {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/auth/me', authRequired, (req, res) => res.json({ user: req.user }));

app.get('/api/webauthn/status', authRequired, async (req, res) => {
  try {
    if (!(await employeeHasColumn('webauthn_credential'))) {
      return res.json({ supported: false, enrolled: false, reason: 'DB column webauthn_credential is missing' });
    }

    const user = await getEmployeeForAuthById(req.user.id);
    const credential = parseStoredCredential(user?.webauthn_credential);
    return res.json({
      supported: true,
      enrolled: !!credential,
      origin: WEBAUTHN_ORIGIN,
      rpID: WEBAUTHN_RP_ID,
    });
  } catch {
    return res.status(500).json({ error: 'Failed to load WebAuthn status' });
  }
});

app.post('/api/webauthn/login-options', async (req, res) => {
  try {
    if (!(await employeeHasColumn('webauthn_credential'))) {
      return res.status(400).json({ error: 'webauthn_credential column is missing. Run SQL patch first.' });
    }

    const username = String(req.body?.username || '').trim();
    if (!username) return res.status(400).json({ error: 'username is required' });

    const user = await getEmployeeForAuthByUsername(username);
    if (!user || !user.is_active) return res.status(404).json({ error: 'User has no WebAuthn credential' });

    const credential = parseStoredCredential(user.webauthn_credential);
    if (!credential) return res.status(404).json({ error: 'User has no WebAuthn credential' });

    const options = await generateAuthenticationOptions({
      rpID: WEBAUTHN_RP_ID,
      userVerification: 'preferred',
      allowCredentials: [{
        id: credential.id,
        type: 'public-key',
        transports: credential.transports,
      }],
    });

    storeChallenge(`login:${username.toLowerCase()}`, options.challenge, { userId: user.id });
    return res.json(options);
  } catch {
    return res.status(500).json({ error: 'Failed to start WebAuthn login' });
  }
});

app.post('/api/webauthn/login-verify', async (req, res) => {
  try {
    if (!(await employeeHasColumn('webauthn_credential'))) {
      return res.status(400).json({ error: 'webauthn_credential column is missing. Run SQL patch first.' });
    }

    const username = String(req.body?.username || '').trim();
    const body = req.body?.body;
    const deviceId = req.body?.deviceId;
    if (!username || !body) return res.status(400).json({ error: 'username and assertion body are required' });

    const challenge = consumeChallenge(`login:${username.toLowerCase()}`);
    if (!challenge) return res.status(400).json({ error: 'WebAuthn challenge expired, retry login' });

    const user = await getEmployeeForAuthByUsername(username);
    if (!user || !user.is_active) return res.status(401).json({ error: 'Invalid credentials' });

    const credential = parseStoredCredential(user.webauthn_credential);
    if (!credential) return res.status(401).json({ error: 'Invalid credentials' });

    const verification = await verifyAuthenticationResponse({
      response: body,
      expectedChallenge: challenge.challenge,
      expectedOrigin: WEBAUTHN_ORIGIN,
      expectedRPID: WEBAUTHN_RP_ID,
      credential: {
        id: credential.id,
        publicKey: fromBase64URL(credential.publicKey),
        counter: Number(credential.counter || 0),
        transports: credential.transports,
      },
    });

    if (!verification.verified) return res.status(401).json({ error: 'WebAuthn verification failed' });

    const cols = await getTableColumns('employees');
    const bind = await upsertDeviceBinding(user, deviceId, cols);
    if (!bind.ok) return res.status(bind.status).json({ error: bind.error });

    const nextCredential = {
      ...credential,
      counter: Number(verification.authenticationInfo?.newCounter || credential.counter || 0),
    };

    await pool.query('UPDATE employees SET webauthn_credential = $1 WHERE id = $2', [JSON.stringify(nextCredential), user.id]);

    return res.json({
      accessToken: makeToken(user),
      user: { id: user.id, name: user.name, username: user.username, role: user.role },
    });
  } catch {
    return res.status(500).json({ error: 'Failed to verify WebAuthn login' });
  }
});

app.get('/api/webauthn/register-options', authRequired, async (req, res) => {
  try {
    if (!(await employeeHasColumn('webauthn_credential'))) {
      return res.status(400).json({ error: 'webauthn_credential column is missing. Run SQL patch first.' });
    }

    const user = await getEmployeeForAuthById(req.user.id);
    if (!user) return res.status(404).json({ error: 'Employee not found' });

    const existing = parseStoredCredential(user.webauthn_credential);
    const options = await generateRegistrationOptions({
      rpName: WEBAUTHN_RP_NAME,
      rpID: WEBAUTHN_RP_ID,
      userID: Buffer.from(user.id),
      userName: user.username,
      userDisplayName: user.name || user.username,
      timeout: 60000,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
      },
      excludeCredentials: existing ? [{
        id: existing.id,
        type: 'public-key',
        transports: existing.transports,
      }] : [],
    });

    storeChallenge(`register:${user.id}`, options.challenge, {});
    return res.json(options);
  } catch {
    return res.status(500).json({ error: 'Failed to start WebAuthn registration' });
  }
});

app.post('/api/webauthn/register-verify', authRequired, async (req, res) => {
  try {
    if (!(await employeeHasColumn('webauthn_credential'))) {
      return res.status(400).json({ error: 'webauthn_credential column is missing. Run SQL patch first.' });
    }

    const challenge = consumeChallenge(`register:${req.user.id}`);
    if (!challenge) return res.status(400).json({ error: 'WebAuthn challenge expired, retry registration' });

    const verification = await verifyRegistrationResponse({
      response: req.body,
      expectedChallenge: challenge.challenge,
      expectedOrigin: WEBAUTHN_ORIGIN,
      expectedRPID: WEBAUTHN_RP_ID,
      requireUserVerification: false,
    });

    if (!verification.verified || !verification.registrationInfo) {
      return res.status(400).json({ error: 'WebAuthn registration failed' });
    }

    const info = verification.registrationInfo;
    const nextCredential = {
      id: typeof info.credential.id === 'string' ? info.credential.id : toBase64URL(info.credential.id),
      publicKey: toBase64URL(info.credential.publicKey),
      counter: Number(info.credential.counter || 0),
      transports: Array.isArray(req.body?.response?.transports) ? req.body.response.transports : [],
    };

    await pool.query('UPDATE employees SET webauthn_credential = $1 WHERE id = $2', [JSON.stringify(nextCredential), req.user.id]);
    return res.json({ verified: true });
  } catch {
    return res.status(500).json({ error: 'Failed to verify WebAuthn registration' });
  }
});

app.post('/api/webauthn/attendance-options', authRequired, async (req, res) => {
  if (req.user.role !== 'employee') return res.status(403).json({ error: 'Forbidden' });

  try {
    if (!(await employeeHasColumn('webauthn_credential'))) {
      return res.status(400).json({ error: 'webauthn_credential column is missing. Run SQL patch first.' });
    }

    const action = req.body?.action;
    if (!['checkin', 'checkout'].includes(action)) {
      return res.status(400).json({ error: 'Invalid action' });
    }

    const user = await getEmployeeForAuthById(req.user.id);
    const credential = parseStoredCredential(user?.webauthn_credential);
    if (!credential) return res.status(400).json({ error: 'No WebAuthn credential for this account' });

    const options = await generateAuthenticationOptions({
      rpID: WEBAUTHN_RP_ID,
      userVerification: 'preferred',
      allowCredentials: [{
        id: credential.id,
        type: 'public-key',
        transports: credential.transports,
      }],
    });

    storeChallenge('attendance:' + req.user.id + ':' + action, options.challenge, { action });
    return res.json(options);
  } catch (error) {
    return res.status(500).json({ error: 'Failed to start attendance verification: ' + (error.message || 'Unknown error') });
  }
});
app.post('/api/webauthn/attendance-verify', authRequired, async (req, res) => {
  if (req.user.role !== 'employee') return res.status(403).json({ error: 'Forbidden' });

  try {
    if (!(await employeeHasColumn('webauthn_credential'))) {
      return res.status(400).json({ error: 'webauthn_credential column is missing. Run SQL patch first.' });
    }

    const action = req.body?.action;
    const assertion = req.body?.assertion;
    const loc = req.body?.loc;
    if (!['checkin', 'checkout'].includes(action) || !assertion) {
      return res.status(400).json({ error: 'action and assertion are required' });
    }

    const challenge = consumeChallenge(`attendance:${req.user.id}:${action}`);
    if (!challenge) return res.status(400).json({ error: 'WebAuthn challenge expired, retry' });

    const user = await getEmployeeForAuthById(req.user.id);
    const credential = parseStoredCredential(user?.webauthn_credential);
    if (!credential) return res.status(400).json({ error: 'No WebAuthn credential for this account' });

    const verification = await verifyAuthenticationResponse({
      response: assertion,
      expectedChallenge: challenge.challenge,
      expectedOrigin: WEBAUTHN_ORIGIN,
      expectedRPID: WEBAUTHN_RP_ID,
      credential: {
        id: credential.id,
        publicKey: fromBase64URL(credential.publicKey),
        counter: Number(credential.counter || 0),
        transports: credential.transports,
      },
    });

    if (!verification.verified) return res.status(401).json({ error: 'WebAuthn verification failed' });

    const nextCredential = {
      ...credential,
      counter: Number(verification.authenticationInfo?.newCounter || credential.counter || 0),
    };
    await pool.query('UPDATE employees SET webauthn_credential = $1 WHERE id = $2', [JSON.stringify(nextCredential), req.user.id]);

    const result = await performAttendanceAction(req.user.id, action, loc);
    return res.status(result.status).json(result.body);
  } catch {
    return res.status(500).json({ error: 'Failed to verify attendance with WebAuthn' });
  }
});

app.get('/api/employee/today', authRequired, async (req, res) => {
  if (req.user.role !== 'employee') return res.status(403).json({ error: 'Forbidden' });

  try {
    const date = todayStr();
    const mode = await getAttendanceMode();
    if (!mode) return res.status(500).json({ error: 'No attendance table found. Run SQL migration first.' });

    const { rows } = mode === 'attendance'
      ? await pool.query('SELECT * FROM attendance WHERE employee_id = $1 AND date = CAST($2 AS DATE)', [req.user.id, date])
      : await pool.query(
        `SELECT id, employee_id, work_date AS date, check_in_time AS check_in, check_out_time AS check_out
         FROM attendance_days
         WHERE employee_id = $1 AND work_date = CAST($2 AS DATE)`,
        [req.user.id, date]
      );

    const day = rows[0] || null;
    return res.json({
      date,
      day,
      canCheckIn: !day || !day.check_in,
      canCheckOut: !!(day && day.check_in && !day.check_out),
      office: { lat: OFFICE_LAT, lng: OFFICE_LNG, radiusMeters: OFFICE_RADIUS_METERS },
    });
  } catch {
    return res.status(500).json({ error: 'Failed to load attendance status' });
  }
});

app.post('/api/employee/checkin', authRequired, async (req, res) => {
  if (req.user.role !== 'employee') return res.status(403).json({ error: 'Forbidden' });

  try {
    const result = await performAttendanceAction(req.user.id, 'checkin', req.body || {});
    return res.status(result.status).json(result.body);
  } catch {
    return res.status(500).json({ error: 'Failed to register check-in' });
  }
});

app.post('/api/employee/checkout', authRequired, async (req, res) => {
  if (req.user.role !== 'employee') return res.status(403).json({ error: 'Forbidden' });

  try {
    const result = await performAttendanceAction(req.user.id, 'checkout', req.body || {});
    return res.status(result.status).json(result.body);
  } catch {
    return res.status(500).json({ error: 'Failed to register check-out' });
  }
});

app.get('/api/employee/salary', authRequired, async (req, res) => {
  if (req.user.role !== 'employee') return res.status(403).json({ error: 'Forbidden' });

  try {
    const month = monthOrCurrent(req.query.month);
    const employee = await getEmployeeById(req.user.id);
    if (!employee) return res.status(404).json({ error: 'Employee not found' });

    const attendance = await loadAttendanceInMonth(req.user.id, month);
    const financials = await loadFinancialsInMonth(req.user.id, month);
    return res.json(buildPayrollSummary(employee, attendance, financials, month));
  } catch {
    return res.status(500).json({ error: 'Failed to build salary statement' });
  }
});

app.get('/api/admin/dashboard/live', authRequired, requireRole('admin'), async (_req, res) => {
  try {
    const employees = (await getAllEmployees()).filter((r) => r.role === 'employee');
    const mode = await getAttendanceMode();
    if (!mode) return res.json({ totalEmployees: employees.length, onlineCount: 0, date: todayStr() });

    const date = todayStr();
    const { rows } = mode === 'attendance'
      ? await pool.query(
        `SELECT employee_id
         FROM attendance
         WHERE date = CAST($1 AS DATE)
           AND check_in IS NOT NULL
           AND check_out IS NULL`,
        [date]
      )
      : await pool.query(
        `SELECT employee_id
         FROM attendance_days
         WHERE work_date = CAST($1 AS DATE)
           AND check_in_time IS NOT NULL
           AND check_out_time IS NULL`,
        [date]
      );

    return res.json({ totalEmployees: employees.length, onlineCount: rows.length, date });
  } catch {
    return res.status(500).json({ error: 'Failed to load live dashboard' });
  }
});

app.get('/api/admin/attendance', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const date = String(req.query.date || todayStr());
    const mode = await getAttendanceMode();
    if (!mode) return res.status(500).json({ error: 'No attendance table found. Run SQL migration first.' });

    const employees = (await getAllEmployees()).filter((r) => r.role === 'employee');
    const { rows } = mode === 'attendance'
      ? await pool.query(
        `SELECT employee_id, check_in, check_out, loc_in, loc_out
         FROM attendance
         WHERE date = CAST($1 AS DATE)`,
        [date]
      )
      : await pool.query(
        `SELECT employee_id, check_in_time AS check_in, check_out_time AS check_out,
                NULL AS loc_in, NULL AS loc_out
         FROM attendance_days
         WHERE work_date = CAST($1 AS DATE)`,
        [date]
      );

    const map = new Map(rows.map((r) => [r.employee_id, r]));
    const data = employees.map((e) => {
      const row = map.get(e.id) || {};
      return {
        employeeId: e.id,
        name: e.name,
        checkIn: row.check_in || null,
        checkOut: row.check_out || null,
        checkInDistance: parseLocDistance(row.loc_in),
        checkOutDistance: parseLocDistance(row.loc_out),
      };
    });

    return res.json({ date, rows: data });
  } catch {
    return res.status(500).json({ error: 'Failed to load attendance report' });
  }
});

app.get('/api/admin/employees', authRequired, requireRole('admin'), async (_req, res) => {
  try {
    const rows = await getAllEmployees();
    const safe = rows.map((r) => {
      const x = { ...r };
      delete x.password_hash;
      return x;
    });
    return res.json({ rows: safe });
  } catch {
    return res.status(500).json({ error: 'Failed to load employees' });
  }
});

app.post('/api/admin/employees', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const { name, username, password, hourlyRate, baseSalary, scheduledStart, breakMinutes } = req.body || {};
    if (!name || !username || !password) {
      return res.status(400).json({ error: 'name, username and password are required' });
    }

    const cols = await getTableColumns('employees');
    const hash = await bcrypt.hash(password, 10);

    const insertCols = ['id', 'name', 'username', 'password_hash'];
    const values = [randomUUID(), name.trim(), username.trim(), hash];

    if (cols.has('role')) { insertCols.push('role'); values.push('employee'); }
    if (cols.has('hourly_rate')) { insertCols.push('hourly_rate'); values.push(Number(hourlyRate || 0)); }
    if (cols.has('base_salary')) { insertCols.push('base_salary'); values.push(Number(baseSalary || 0)); }
    if (cols.has('scheduled_start')) { insertCols.push('scheduled_start'); values.push(scheduledStart || '09:00'); }
    if (cols.has('break_minutes')) { insertCols.push('break_minutes'); values.push(Number(breakMinutes || 60)); }
    if (cols.has('is_active')) { insertCols.push('is_active'); values.push(true); }

    const params = insertCols.map((_, i) => `$${i + 1}`);
    await pool.query(`INSERT INTO employees (${insertCols.join(', ')}) VALUES (${params.join(', ')})`, values);

    return res.json({ success: true });
  } catch (error) {
    if (String(error.message || '').includes('duplicate key')) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    return res.status(500).json({ error: 'Failed to create employee' });
  }
});

app.patch('/api/admin/employees/:id', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const { hourlyRate, baseSalary, scheduledStart, breakMinutes } = req.body || {};
    const cols = await getTableColumns('employees');

    const sets = [];
    const values = [];

    if (cols.has('hourly_rate')) { sets.push(`hourly_rate = $${values.length + 1}`); values.push(Number(hourlyRate || 0)); }
    if (cols.has('base_salary')) { sets.push(`base_salary = $${values.length + 1}`); values.push(Number(baseSalary || 0)); }
    if (cols.has('scheduled_start')) { sets.push(`scheduled_start = $${values.length + 1}`); values.push(scheduledStart || '09:00'); }
    if (cols.has('break_minutes')) { sets.push(`break_minutes = $${values.length + 1}`); values.push(Number(breakMinutes || 60)); }
    if (cols.has('updated_at')) sets.push('updated_at = NOW()');

    if (!sets.length) {
      return res.status(400).json({ error: 'Employees table missing payroll columns. Run SQL patch first.' });
    }

    values.push(req.params.id);
    const { rowCount } = await pool.query(`UPDATE employees SET ${sets.join(', ')} WHERE id = $${values.length}`, values);

    if (!rowCount) return res.status(404).json({ error: 'Employee not found' });
    return res.json({ success: true });
  } catch {
    return res.status(500).json({ error: 'Failed to update employee' });
  }
});

app.post('/api/admin/employees/:id/toggle', authRequired, requireRole('admin'), async (req, res) => {
  try {
    if (!(await employeeHasColumn('is_active'))) {
      return res.status(400).json({ error: 'is_active column missing. Run SQL patch first.' });
    }

    const setUpdated = (await employeeHasColumn('updated_at')) ? ', updated_at = NOW()' : '';
    const { rowCount } = await pool.query(
      `UPDATE employees
       SET is_active = NOT COALESCE(is_active, true)${setUpdated}
       WHERE id = $1`,
      [req.params.id]
    );

    if (!rowCount) return res.status(404).json({ error: 'Employee not found' });
    return res.json({ success: true });
  } catch {
    return res.status(500).json({ error: 'Failed to update employee status' });
  }
});

app.post('/api/admin/employees/:id/reset-device', authRequired, requireRole('admin'), async (req, res) => {
  try {
    if (!(await employeeHasColumn('device_id'))) {
      return res.status(400).json({ error: 'device_id column missing. Run SQL patch first.' });
    }

    const setUpdated = (await employeeHasColumn('updated_at')) ? ', updated_at = NOW()' : '';
    const { rowCount } = await pool.query(`UPDATE employees SET device_id = NULL${setUpdated} WHERE id = $1`, [req.params.id]);

    if (!rowCount) return res.status(404).json({ error: 'Employee not found' });
    return res.json({ success: true });
  } catch {
    return res.status(500).json({ error: 'Failed to reset device binding' });
  }
});

app.delete('/api/admin/employees/:id', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const employeeId = req.params.id;
    const { rows: roleRows } = await pool.query('SELECT role FROM employees WHERE id = $1', [employeeId]);
    if (!roleRows.length) return res.status(404).json({ error: 'Employee not found' });
    if ((roleRows[0].role || 'employee') === 'admin') return res.status(400).json({ error: 'Cannot delete admin account' });

    await pool.query('BEGIN');
    if (await tableExists('attendance')) await pool.query('DELETE FROM attendance WHERE employee_id = $1', [employeeId]);
    if (await tableExists('attendance_days')) await pool.query('DELETE FROM attendance_days WHERE employee_id = $1', [employeeId]);
    if (await tableExists('financials')) await pool.query('DELETE FROM financials WHERE employee_id = $1', [employeeId]);
    if (await tableExists('payroll_runs')) await pool.query('DELETE FROM payroll_runs WHERE employee_id = $1', [employeeId]);
    await pool.query('DELETE FROM employees WHERE id = $1', [employeeId]);
    await pool.query('COMMIT');

    return res.json({ success: true });
  } catch {
    await pool.query('ROLLBACK').catch(() => {});
    return res.status(500).json({ error: 'Failed to delete employee' });
  }
});

app.get('/api/admin/financials', authRequired, requireRole('admin'), async (req, res) => {
  try {
    if (!(await tableExists('financials'))) {
      return res.status(400).json({ error: 'financials table is missing in database. Run SQL patch first.' });
    }

    const month = monthOrCurrent(req.query.month);
    const from = `${month}-01`;

    const { rows } = await pool.query(
      `SELECT f.id, f.employee_id, e.name, e.username, f.type, f.amount, f.reason, f.date
       FROM financials f
       JOIN employees e ON e.id = f.employee_id
       WHERE f.date >= CAST($1 AS DATE)
         AND f.date < (CAST($1 AS DATE) + INTERVAL '1 month')
       ORDER BY f.date DESC`,
      [from]
    );

    return res.json({ rows });
  } catch {
    return res.status(500).json({ error: 'Failed to load financial entries' });
  }
});

app.post('/api/admin/financials', authRequired, requireRole('admin'), async (req, res) => {
  try {
    if (!(await tableExists('financials'))) {
      return res.status(400).json({ error: 'financials table is missing in database. Run SQL patch first.' });
    }

    const { employeeId, type, amount, reason, date } = req.body || {};
    if (!employeeId || !['bonus', 'deduction'].includes(type) || Number(amount) < 0 || !date) {
      return res.status(400).json({ error: 'Invalid financial entry payload' });
    }

    await pool.query(
      `INSERT INTO financials (id, employee_id, type, amount, reason, date)
       VALUES ($1, $2, $3, $4, $5, CAST($6 AS DATE))`,
      [randomUUID(), employeeId, type, Number(amount), reason || '', date]
    );

    return res.json({ success: true });
  } catch {
    return res.status(500).json({ error: 'Failed to save financial entry' });
  }
});

app.get('/api/admin/payroll', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const month = monthOrCurrent(req.query.month);
    const employees = (await getAllEmployees()).filter((r) => r.role === 'employee' && r.is_active);

    const rows = [];
    for (const e of employees) {
      const attendance = await loadAttendanceInMonth(e.id, month);
      const financials = await loadFinancialsInMonth(e.id, month);
      rows.push(buildPayrollSummary(e, attendance, financials, month));
    }

    return res.json({ month, rows });
  } catch {
    return res.status(500).json({ error: 'Failed to build payroll' });
  }
});

app.post('/api/admin/payroll/approve', authRequired, requireRole('admin'), async (req, res) => {
  try {
    if (!(await tableExists('payroll_runs'))) {
      return res.status(400).json({ error: 'payroll_runs table is missing in database. Run SQL patch first.' });
    }

    const { employeeId, month, totalNet } = req.body || {};
    if (!employeeId || !/^\d{4}-\d{2}$/.test(String(month || ''))) {
      return res.status(400).json({ error: 'Invalid approval payload' });
    }

    await pool.query(
      `INSERT INTO payroll_runs (id, employee_id, month, total_net, approved_by, approved_at)
       VALUES ($1, $2, $3, $4, $5, NOW())
       ON CONFLICT (employee_id, month)
       DO UPDATE SET
         total_net = EXCLUDED.total_net,
         approved_by = EXCLUDED.approved_by,
         approved_at = NOW()`,
      [randomUUID(), employeeId, month, Number(totalNet || 0), req.user.id]
    );

    return res.json({ success: true });
  } catch {
    return res.status(500).json({ error: 'Failed to approve payroll' });
  }
});

app.get('/api/admin/export', authRequired, requireRole('admin'), async (req, res) => {
  try {
    const from = String(req.query.from || todayStr());
    const to = String(req.query.to || todayStr());

    const wb = new ExcelJS.Workbook();
    const mode = await getAttendanceMode();

    if (mode) {
      const wsA = wb.addWorksheet('Attendance');
      wsA.columns = [
        { header: 'Employee', key: 'name', width: 28 },
        { header: 'Date', key: 'date', width: 14 },
        { header: 'Check In', key: 'check_in', width: 24 },
        { header: 'Check Out', key: 'check_out', width: 24 },
        { header: 'In Distance (m)', key: 'in_dist', width: 16 },
        { header: 'Out Distance (m)', key: 'out_dist', width: 16 },
      ];

      const { rows } = mode === 'attendance'
        ? await pool.query(
          `SELECT e.name, a.date, a.check_in, a.check_out, a.loc_in, a.loc_out
           FROM attendance a
           JOIN employees e ON e.id = a.employee_id
           WHERE a.date >= CAST($1 AS DATE) AND a.date <= CAST($2 AS DATE)
           ORDER BY a.date ASC, e.name ASC`,
          [from, to]
        )
        : await pool.query(
          `SELECT e.name, a.work_date AS date, a.check_in_time AS check_in, a.check_out_time AS check_out,
                  NULL AS loc_in, NULL AS loc_out
           FROM attendance_days a
           JOIN employees e ON e.id = a.employee_id
           WHERE a.work_date >= CAST($1 AS DATE) AND a.work_date <= CAST($2 AS DATE)
           ORDER BY a.work_date ASC, e.name ASC`,
          [from, to]
        );

      for (const r of rows) {
        wsA.addRow({
          name: r.name,
          date: r.date,
          check_in: r.check_in,
          check_out: r.check_out,
          in_dist: parseLocDistance(r.loc_in),
          out_dist: parseLocDistance(r.loc_out),
        });
      }
    }

    const wsP = wb.addWorksheet('Payroll');
    wsP.columns = [
      { header: 'Month', key: 'month', width: 12 },
      { header: 'Employee', key: 'name', width: 28 },
      { header: 'Worked Hours', key: 'hours', width: 14 },
      { header: 'Bonuses', key: 'bonuses', width: 12 },
      { header: 'Deductions', key: 'deductions', width: 14 },
      { header: 'Net', key: 'net', width: 14 },
    ];

    const startMonth = from.slice(0, 7);
    const employees = (await getAllEmployees()).filter((r) => r.role === 'employee');
    for (const e of employees) {
      const attendance = await loadAttendanceInMonth(e.id, startMonth);
      const financials = await loadFinancialsInMonth(e.id, startMonth);
      const payroll = buildPayrollSummary(e, attendance, financials, startMonth);
      wsP.addRow({
        month: startMonth,
        name: e.name,
        hours: payroll.totals.workedHours,
        bonuses: payroll.totals.bonuses,
        deductions: payroll.totals.lateDeduction + payroll.totals.manualDeductions,
        net: payroll.totals.net,
      });
    }

    res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
    res.setHeader('Content-Disposition', `attachment; filename="injaz_report_${from}_to_${to}.xlsx"`);

    await wb.xlsx.write(res);
    return res.end();
  } catch {
    return res.status(500).json({ error: 'Failed to export report' });
  }
});

app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/', (_req, res) => res.redirect('/employee/login.html'));
app.use((_req, res) => res.status(404).json({ error: 'Route not found' }));

app.listen(PORT, () => {
  console.log(`Injaz server listening on http://localhost:${PORT}`);
});







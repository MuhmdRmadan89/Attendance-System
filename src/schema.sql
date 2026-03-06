CREATE EXTENSION IF NOT EXISTS "pgcrypto";

CREATE TABLE IF NOT EXISTS employees (
  id UUID PRIMARY KEY,
  name TEXT NOT NULL,
  username TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'employee' CHECK (role IN ('admin', 'employee')),
  device_id TEXT,
  webauthn_credential JSONB,
  hourly_rate NUMERIC(12,2) NOT NULL DEFAULT 0,
  base_salary NUMERIC(12,2) NOT NULL DEFAULT 0,
  scheduled_start TIME NOT NULL DEFAULT '09:00',
  break_minutes INT NOT NULL DEFAULT 60,
  is_active BOOLEAN NOT NULL DEFAULT TRUE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS attendance (
  id UUID PRIMARY KEY,
  employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  date DATE NOT NULL,
  check_in TIMESTAMPTZ,
  check_out TIMESTAMPTZ,
  loc_in JSONB,
  loc_out JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (employee_id, date)
);

CREATE TABLE IF NOT EXISTS financials (
  id UUID PRIMARY KEY,
  employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  type TEXT NOT NULL CHECK (type IN ('bonus', 'deduction')),
  amount NUMERIC(12,2) NOT NULL CHECK (amount >= 0),
  reason TEXT,
  date DATE NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS payroll_runs (
  id UUID PRIMARY KEY,
  employee_id UUID NOT NULL REFERENCES employees(id) ON DELETE CASCADE,
  month TEXT NOT NULL,
  total_net NUMERIC(12,2) NOT NULL DEFAULT 0,
  approved_by UUID REFERENCES employees(id),
  approved_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  UNIQUE (employee_id, month)
);

CREATE INDEX IF NOT EXISTS idx_attendance_emp_date ON attendance(employee_id, date);
CREATE INDEX IF NOT EXISTS idx_financials_emp_date ON financials(employee_id, date);

ALTER TABLE employees ENABLE ROW LEVEL SECURITY;
ALTER TABLE attendance ENABLE ROW LEVEL SECURITY;
ALTER TABLE financials ENABLE ROW LEVEL SECURITY;
ALTER TABLE payroll_runs ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS employees_policy ON employees;
CREATE POLICY employees_policy ON employees USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS attendance_policy ON attendance;
CREATE POLICY attendance_policy ON attendance USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS financials_policy ON financials;
CREATE POLICY financials_policy ON financials USING (true) WITH CHECK (true);

DROP POLICY IF EXISTS payroll_runs_policy ON payroll_runs;
CREATE POLICY payroll_runs_policy ON payroll_runs USING (true) WITH CHECK (true);

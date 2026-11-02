/**
 * Environment Sanitizer & Secret Redactor
 *
 * Ensures that Python C and any descendant native processes receive a strictly
 * allowlisted, credential-stripped environment. Artifact upload credentials
 * (ACTIONS_RUNTIME_TOKEN, ACTIONS_RESULTS_URL, GITHUB_TOKEN, etc.) remain strictly
 * within Node supervisor's own process.
 */

// Explicitly forbidden environment variable names
export const FORBIDDEN_ENV_KEYS = new Set([
  'ACTIONS_RUNTIME_TOKEN',
  'ACTIONS_RESULTS_URL',
  'ACTIONS_ID_TOKEN_REQUEST_URL',
  'ACTIONS_ID_TOKEN_REQUEST_TOKEN',
  'GITHUB_TOKEN',
  'INPUT_GITHUB_TOKEN',
  'NODE_AUTH_TOKEN',
  'NPM_TOKEN',
  'AWS_ACCESS_KEY_ID',
  'AWS_SECRET_ACCESS_KEY',
  'AWS_SESSION_TOKEN',
]);

// Patterns matching sensitive credentials or keys
export const SENSITIVE_KEY_PATTERNS = [
  /TOKEN/i,
  /SECRET/i,
  /KEY/i,
  /AUTH/i,
  /CREDENTIAL/i,
  /PASSWORD/i,
  /PRIVATE/i,
  /BEARER/i,
];

// Safe allowlist of environment variable names necessary for system, Python, and Git execution
export const ALLOWED_ENV_KEYS = new Set([
  'PATH',
  'HOME',
  'USER',
  'LOGNAME',
  'SHELL',
  'TMPDIR',
  'TEMP',
  'TMP',
  'LANG',
  'LC_ALL',
  'LC_CTYPE',
  'LC_MESSAGES',
  'TERM',
  'CI',
  'GITHUB_ACTIONS',
  'GITHUB_WORKSPACE',
  'GITHUB_REPOSITORY',
  'GITHUB_RUN_ID',
  'GITHUB_RUN_ATTEMPT',
  'GITHUB_JOB',
  'GITHUB_SHA',
  'GITHUB_REF',
  'GITHUB_EVENT_NAME',
  'RUNNER_OS',
  'RUNNER_ARCH',
  'RUNNER_NAME',
  'RUNNER_TEMP',
  'RUNNER_TOOL_CACHE',
  'PYTHONPATH',
  'PYTHONUNBUFFERED',
  'PYTHONDONTWRITEBYTECODE',
  'SYSTEMROOT',
  'COMSPEC',
  'PATHEXT',
  'WINDIR',
]);

/**
 * Collect sensitive string values from environment for log redaction.
 */
export function extractSensitiveValues(env = process.env) {
  const values = new Set();
  for (const [key, value] of Object.entries(env)) {
    if (!value || typeof value !== 'string' || value.length < 4) continue;
    if (FORBIDDEN_ENV_KEYS.has(key)) {
      values.add(value);
      continue;
    }
    for (const pattern of SENSITIVE_KEY_PATTERNS) {
      if (pattern.test(key)) {
        values.add(value);
        break;
      }
    }
  }
  return Array.from(values);
}

/**
 * Sanitize environment for child execution:
 * 1. Only include keys in ALLOWED_ENV_KEYS.
 * 2. Exclude keys in FORBIDDEN_ENV_KEYS.
 * 3. Exclude keys matching SENSITIVE_KEY_PATTERNS.
 * 4. Exclude any variables whose values match sensitive token/credential values.
 */
export function sanitizeEnvironment(parentEnv = process.env) {
  const sanitized = {};
  const sensitiveValues = extractSensitiveValues(parentEnv);

  for (const [key, value] of Object.entries(parentEnv)) {
    if (!ALLOWED_ENV_KEYS.has(key)) {
      continue;
    }
    if (FORBIDDEN_ENV_KEYS.has(key)) {
      continue;
    }
    let isSensitiveKey = false;
    for (const pattern of SENSITIVE_KEY_PATTERNS) {
      if (pattern.test(key)) {
        isSensitiveKey = true;
        break;
      }
    }
    if (isSensitiveKey) {
      continue;
    }

    // Verify value does not contain any sensitive tokens
    let containsSensitive = false;
    if (typeof value === 'string' && value.length > 0) {
      for (const secret of sensitiveValues) {
        if (value.includes(secret)) {
          containsSensitive = true;
          break;
        }
      }
    }
    if (containsSensitive) {
      continue;
    }

    sanitized[key] = value;
  }

  // Ensure python runs in unbuffered mode without bytecode pollution
  sanitized.PYTHONUNBUFFERED = '1';
  sanitized.PYTHONDONTWRITEBYTECODE = '1';

  return sanitized;
}

/**
 * Redact sensitive values from log output.
 */
export function redactSecrets(text, sensitiveValues = null) {
  if (typeof text !== 'string') return text;
  const values = sensitiveValues || extractSensitiveValues();
  let redacted = text;
  for (const val of values) {
    if (!val || val.length < 4) continue;
    redacted = redacted.split(val).join('[REDACTED]');
  }
  return redacted;
}

/**
 * Dedicated IPC Transport for Strict Controller
 *
 * Implements newline-delimited JSON (NDJSON) over dedicated file descriptors:
 * - fd3: Request stream (Child -> Supervisor)
 * - fd4: Ack stream (Supervisor -> Child)
 *
 * Workload stdout is NEVER used for protocol control.
 */

export const IMMUTABLE_BINDING_FIELDS = [
  'protocol_version', 'request_id', 'invocation_id', 'execution_kind',
  'repository', 'run_id', 'run_attempt', 'job_id', 'job_key',
  'p_sha', 'w_sha', 'c_sha', 'fixture_sha256', 'strict_manifest_sha256', 'snapshot_kind',
  'chain_id', 'unit', 'native_attempt', 'snapshot_sequence',
  'archive_bytes', 'archive_sha256',
];

const SHA256_HEX_REGEX = /^[0-9a-f]{64}$/;
const SHA1_HEX_REGEX = /^[0-9a-f]{40}$/;
const CHAIN_ID_VALID_REGEX = /^[0-9a-f]{32}$/;

/**
 * Validate incoming request structure from Python C
 */
export function validateRequest(req) {
  if (!req || typeof req !== 'object' || Array.isArray(req)) {
    return { valid: false, error: 'Request must be an object' };
  }
  for (const field of IMMUTABLE_BINDING_FIELDS) {
    if (!Object.hasOwn(req, field)) return { valid: false, error: `Missing ${field}` };
  }
  if (req.event !== 'persistence-request' || req.protocol_version !== 1) {
    return { valid: false, error: 'Invalid event or protocol version' };
  }
  for (const field of ['request_id', 'invocation_id', 'repository', 'job_key', 'unit']) {
    if (typeof req[field] !== 'string' || !req[field].trim()) {
      return { valid: false, error: `Invalid ${field}` };
    }
  }
  for (const field of ['run_id', 'run_attempt', 'job_id']) {
    if (typeof req[field] !== 'string' || !/^[1-9][0-9]*$/.test(req[field])) {
      return { valid: false, error: `Invalid ${field}` };
    }
  }
  if (!['synthetic', 'native'].includes(req.execution_kind)) {
    return { valid: false, error: 'Invalid execution kind' };
  }
  if (req.execution_kind === 'synthetic'
      ? typeof req.fixture_sha256 !== 'string' || !SHA256_HEX_REGEX.test(req.fixture_sha256)
      : req.fixture_sha256 !== null) {
    return { valid: false, error: 'Invalid fixture digest' };
  }
  if (req.execution_kind === 'native'
      ? typeof req.strict_manifest_sha256 !== 'string' || !SHA256_HEX_REGEX.test(req.strict_manifest_sha256)
      : req.strict_manifest_sha256 !== null) {
    return { valid: false, error: 'Invalid strict manifest digest' };
  }
  for (const field of ['p_sha', 'w_sha', 'c_sha']) {
    if (typeof req[field] !== 'string' || !SHA1_HEX_REGEX.test(req[field])) {
      return { valid: false, error: `Invalid ${field}` };
    }
  }
  if (!['plan', 'prechain-failure', 'checkpoint', 'terminal-envelope'].includes(req.snapshot_kind)) {
    return { valid: false, error: 'Invalid snapshot kind' };
  }
  if (['plan', 'prechain-failure'].includes(req.snapshot_kind)) {
    if (req.chain_id !== null) return { valid: false, error: 'Prechain snapshot requires null chain' };
    if (req.snapshot_kind === 'plan' && req.unit !== 'plan') return { valid: false, error: 'Invalid plan unit' };
    if (req.snapshot_kind === 'prechain-failure' && req.unit !== 'pin') return { valid: false, error: 'Invalid prechain failure unit' };
  } else if (typeof req.chain_id !== 'string' || !CHAIN_ID_VALID_REGEX.test(req.chain_id)) {
    return { valid: false, error: 'Invalid established chain identity' };
  }
  for (const field of ['native_attempt', 'snapshot_sequence', 'archive_bytes']) {
    if (!Number.isSafeInteger(req[field]) || req[field] < 1) return { valid: false, error: `Invalid ${field}` };
  }
  if (typeof req.archive_path !== 'string' || !req.archive_path.trim() ||
      typeof req.archive_sha256 !== 'string' || !SHA256_HEX_REGEX.test(req.archive_sha256)) {
    return { valid: false, error: 'Invalid archive' };
  }
  return { valid: true };
}

/**
 * Validate an ACK against its originating request
 */
export function validateAck(ack, req) {
  if (!ack || typeof ack !== 'object' || Array.isArray(ack)) {
    return { valid: false, reason: 'ACK must be a non-null JSON object' };
  }

  if (ack.event !== 'persistence-ack') return { valid: false, reason: 'Invalid ACK event' };
  for (const field of IMMUTABLE_BINDING_FIELDS) {
    if (!Object.hasOwn(ack, field) || ack[field] !== req[field]) {
      return { valid: false, reason: `Mismatched ACK binding: ${field}` };
    }
  }

  if (ack.verified !== true) {
    return {
      valid: false,
      reason: ack.error || 'ACK verified flag is false',
    };
  }

  if (ack.artifact_id === undefined || ack.artifact_id === null || ack.artifact_id === '') {
    return { valid: false, reason: 'ACK missing valid artifact_id' };
  }

  if (ack.downloaded_bytes !== req.archive_bytes) {
    return {
      valid: false,
      reason: `Byte count mismatch: expected ${req.archive_bytes}, got ${ack.downloaded_bytes}`,
    };
  }

  if (ack.downloaded_sha256 !== req.archive_sha256) {
    return {
      valid: false,
      reason: `SHA256 mismatch: expected ${req.archive_sha256}, got ${ack.downloaded_sha256}`,
    };
  }

  return { valid: true };
}

/**
 * Write newline-delimited JSON ACK to writable stream (fd4) with bounded timeout
 */
export function writeIpcAck(writableStream, ackData, timeoutMs = 5000) {
  const line = JSON.stringify(ackData) + '\n';
  return new Promise((resolve, reject) => {
    if (!writableStream || writableStream.destroyed) {
      return reject(new Error('ACK stream is destroyed or unavailable'));
    }
    const timer = setTimeout(() => {
      reject(new Error(`writeIpcAck timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    writableStream.write(line, 'utf8', (err) => {
      clearTimeout(timer);
      if (err) reject(err);
      else resolve();
    });
  });
}

/**
 * Create NDJSON line reader on readable stream (fd3) with bounded buffer and error handling
 */
export function createIpcReader(readableStream, onLine) {
  let buffer = '';
  const MAX_BUFFER_SIZE = 10 * 1024 * 1024; // 10MB safety cap

  readableStream.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
    if (buffer.length > MAX_BUFFER_SIZE) {
      readableStream.emit('error', new Error('IPC fd3 buffer overflow exceeded 10MB cap'));
      return;
    }
    let idx;
    while ((idx = buffer.indexOf('\n')) !== -1) {
      const line = buffer.slice(0, idx).trim();
      buffer = buffer.slice(idx + 1);
      if (line) {
        try {
          const parsed = JSON.parse(line);
          onLine(parsed);
        } catch (err) {
          readableStream.emit('error', new Error(`Invalid JSON received over IPC fd3: ${err.message}`));
        }
      }
    }
  });

  readableStream.on('end', () => {
    const remaining = buffer.trim();
    if (remaining) {
      try {
        const parsed = JSON.parse(remaining);
        onLine(parsed);
      } catch (err) {
        readableStream.emit('error', new Error(`Invalid trailing JSON received over IPC fd3: ${err.message}`));
      }
    }
  });

  readableStream.on('error', (err) => {
    // Prevent uncaught stream errors from crashing process without supervisor capture
    console.error(`createIpcReader stream error: ${err.message}`);
  });
}

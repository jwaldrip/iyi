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
  'request_id',
  'repository',
  'run_id',
  'run_attempt',
  'job_id',
  'p_sha',
  'w_sha',
  'c_sha',
  'chain_id',
  'unit',
  'native_attempt',
  'snapshot_sequence',
];

const SHA256_HEX_REGEX = /^[0-9a-fA-F]{64}$/;
const SHA1_HEX_REGEX = /^[0-9a-fA-F]{40}$/;
const CHAIN_ID_VALID_REGEX = /^[0-9a-zA-Z_-]+$/;

/**
 * Validate incoming request structure from Python C
 */
export function validateRequest(req) {
  if (!req || typeof req !== 'object' || Array.isArray(req)) {
    return { valid: false, error: 'Request must be a non-null JSON object' };
  }

  // Ensure all immutable binding fields are present
  for (const field of IMMUTABLE_BINDING_FIELDS) {
    if (!(field in req) || req[field] === undefined) {
      return { valid: false, error: `Missing required immutable field: ${field}` };
    }
  }

  if (typeof req.unit !== 'string' || !req.unit.trim()) {
    return { valid: false, error: 'Invalid or missing unit' };
  }

  // Pre-pin plan snapshot requires typed chain_id: null (chain does not exist prior to pin).
  // Post-pin stages require a valid, nonempty chain_id string.
  // Sentinel values ('nochain', 'null') or empty/absent values are strictly forbidden.
  if (req.unit === 'plan') {
    if (req.chain_id !== null) {
      return {
        valid: false,
        error: `Unit 'plan' requires typed chain_id: null (pre-pin), got ${typeof req.chain_id === 'string' ? `'${req.chain_id}'` : req.chain_id}`,
      };
    }
  } else {
    if (req.chain_id === null) {
      return {
        valid: false,
        error: `Unit '${req.unit}' requires valid chain_id (chain_id: null accepted only for unit plan)`,
      };
    }
    if (typeof req.chain_id !== 'string' || !req.chain_id.trim()) {
      return { valid: false, error: 'Missing required immutable field: chain_id' };
    }
    if (req.chain_id === 'nochain' || req.chain_id === 'null') {
      return {
        valid: false,
        error: `Invalid chain_id: sentinel forge '${req.chain_id}' is forbidden`,
      };
    }
    if (!CHAIN_ID_VALID_REGEX.test(req.chain_id)) {
      return {
        valid: false,
        error: `Invalid chain_id format for unit '${req.unit}': '${req.chain_id}'`,
      };
    }
  }

  // Ensure all other immutable binding fields are non-empty and well-formed
  for (const field of IMMUTABLE_BINDING_FIELDS) {
    if (field === 'chain_id') continue;
    if (req[field] === null || req[field] === '') {
      return { valid: false, error: `Missing required immutable field: ${field}` };
    }
  }

  for (const shaField of ['p_sha', 'w_sha', 'c_sha']) {
    if (typeof req[shaField] !== 'string' || !SHA1_HEX_REGEX.test(req[shaField])) {
      return { valid: false, error: `Invalid ${shaField}: ${req[shaField]} (must be 40-char hex SHA)` };
    }
  }

  if (typeof req.native_attempt !== 'number' || !Number.isInteger(req.native_attempt) || req.native_attempt < 1) {
    return { valid: false, error: `Invalid native_attempt: ${req.native_attempt} (must be positive integer)` };
  }

  if (typeof req.snapshot_sequence !== 'number' || !Number.isInteger(req.snapshot_sequence) || req.snapshot_sequence < 1) {
    return { valid: false, error: `Invalid snapshot_sequence: ${req.snapshot_sequence} (must be positive integer)` };
  }

  if (typeof req.archive_path !== 'string' || !req.archive_path.trim()) {
    return { valid: false, error: 'Invalid or missing archive_path' };
  }

  if (typeof req.archive_bytes !== 'number' || req.archive_bytes <= 0 || !Number.isInteger(req.archive_bytes)) {
    return { valid: false, error: `Invalid archive_bytes: ${req.archive_bytes} (must be positive integer)` };
  }

  if (typeof req.archive_sha256 !== 'string' || !SHA256_HEX_REGEX.test(req.archive_sha256)) {
    return { valid: false, error: `Invalid archive_sha256: ${req.archive_sha256} (must be 64-char hex)` };
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

  // Verify all immutable binding fields match with strict typed validation
  for (const field of IMMUTABLE_BINDING_FIELDS) {
    if (!(field in ack) || ack[field] === undefined) {
      return { valid: false, reason: `Missing binding field in ACK: ${field}` };
    }
    if (field === 'chain_id') {
      if (req.chain_id === null) {
        if (ack.chain_id !== null) {
          return {
            valid: false,
            reason: `Mismatched binding field chain_id: expected null, got ${ack.chain_id}`,
          };
        }
      } else {
        if (ack.chain_id !== req.chain_id) {
          return {
            valid: false,
            reason: `Mismatched binding field chain_id: expected ${req.chain_id}, got ${ack.chain_id}`,
          };
        }
      }
    } else {
      if (String(ack[field]) !== String(req[field])) {
        return {
          valid: false,
          reason: `Mismatched binding field ${field}: expected ${req[field]}, got ${ack[field]}`,
        };
      }
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

  if (Number(ack.downloaded_bytes) !== Number(req.archive_bytes)) {
    return {
      valid: false,
      reason: `Byte count mismatch: expected ${req.archive_bytes}, got ${ack.downloaded_bytes}`,
    };
  }

  if (String(ack.downloaded_sha256).toLowerCase() !== String(req.archive_sha256).toLowerCase()) {
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

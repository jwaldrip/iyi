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

/**
 * Validate incoming request structure from Python C
 */
export function validateRequest(req) {
  if (!req || typeof req !== 'object') {
    return { valid: false, error: 'Request must be a non-null JSON object' };
  }

  for (const field of IMMUTABLE_BINDING_FIELDS) {
    if (req[field] === undefined || req[field] === null || req[field] === '') {
      return { valid: false, error: `Missing required immutable field: ${field}` };
    }
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
  if (!ack || typeof ack !== 'object') {
    return { valid: false, reason: 'ACK must be a non-null JSON object' };
  }

  // Verify all immutable binding fields match
  for (const field of IMMUTABLE_BINDING_FIELDS) {
    if (String(ack[field]) !== String(req[field])) {
      return {
        valid: false,
        reason: `Mismatched binding field ${field}: expected ${req[field]}, got ${ack[field]}`,
      };
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
 * Write newline-delimited JSON ACK to writable stream (fd4)
 */
export function writeIpcAck(writableStream, ackData) {
  const line = JSON.stringify(ackData) + '\n';
  return new Promise((resolve, reject) => {
    if (writableStream.destroyed) {
      return reject(new Error('ACK stream is destroyed'));
    }
    writableStream.write(line, 'utf8', (err) => {
      if (err) reject(err);
      else resolve();
    });
  });
}

/**
 * Create NDJSON line reader on readable stream (fd3)
 */
export function createIpcReader(readableStream, onLine) {
  let buffer = '';

  readableStream.on('data', (chunk) => {
    buffer += chunk.toString('utf8');
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
}

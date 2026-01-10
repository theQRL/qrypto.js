/**
 * Security utilities for Dilithium5
 *
 * IMPORTANT: JavaScript cannot guarantee secure memory zeroization.
 * See SECURITY.md for details on limitations.
 */

/**
 * Attempts to zero out a Uint8Array buffer.
 *
 * WARNING: This is a BEST-EFFORT operation. Due to JavaScript/JIT limitations:
 * - The write may be optimized away if the buffer is unused afterward
 * - Copies may exist in garbage collector memory
 * - Data may have been swapped to disk
 *
 * For high-security applications, consider native implementations (go-qrllib)
 * or hardware security modules.
 *
 * @param {Uint8Array} buffer - The buffer to zero
 * @returns {void}
 */
export function zeroize(buffer) {
  if (!(buffer instanceof Uint8Array)) {
    throw new TypeError('zeroize requires a Uint8Array');
  }
  // Use fill(0) for zeroing - best effort
  buffer.fill(0);
  // Additional volatile-like access to discourage optimization
  // (This is a hint to the JIT, not a guarantee)
  if (buffer.length > 0 && buffer[0] !== 0) {
    throw new Error('zeroize failed'); // Should never happen
  }
}

/**
 * Checks if a buffer is all zeros.
 * Uses constant-time comparison to avoid timing leaks.
 *
 * @param {Uint8Array} buffer - The buffer to check
 * @returns {boolean} True if all bytes are zero
 */
export function isZero(buffer) {
  if (!(buffer instanceof Uint8Array)) {
    throw new TypeError('isZero requires a Uint8Array');
  }
  let acc = 0;
  for (let i = 0; i < buffer.length; i++) {
    acc |= buffer[i];
  }
  return acc === 0;
}

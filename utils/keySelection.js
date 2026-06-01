/**
 * Shared rules for public key discovery:
 * - status = 'active'
 * - discoverable = 1
 * - prefer is_preferred = 1; if none or duplicates, use newest created_at
 */

/**
 * @param {import('../db/database.js').default} queryDb
 * @param {string} email normalized email
 * @param {string|null} algorithm optional algorithm filter
 * @returns {Promise<object|undefined>}
 */
export async function selectDiscoverableKeyForEmail(queryDb, email, algorithm = null) {
  const params = [email];
  let algoClause = '';
  if (algorithm) {
    algoClause = ' AND algorithm = ?';
    params.push(algorithm);
  }

  return queryDb.prepare(`
    SELECT key_id, algorithm, public_key, label
    FROM keys
    WHERE email = ?
      AND status = 'active'
      AND discoverable = 1
      ${algoClause}
    ORDER BY is_preferred DESC, created_at DESC
    LIMIT 1
  `).get(...params);
}

/**
 * Clears duplicate preferred flags for one user+algorithm (keeps newest active preferred).
 * @param {import('../db/database.js').default} queryDb
 */
export async function normalizePreferredKeys(queryDb, email, algorithm) {
  const rows = await queryDb.prepare(`
    SELECT key_id FROM keys
    WHERE email = ? AND algorithm = ? AND status = 'active' AND is_preferred = 1
    ORDER BY created_at DESC
  `).all(email, algorithm);

  if (rows.length <= 1) return;

  const keepId = rows[0].key_id;
  await queryDb.prepare(`
    UPDATE keys SET is_preferred = 0
    WHERE email = ? AND algorithm = ? AND status = 'active'
      AND is_preferred = 1 AND key_id != ?
  `).run(email, algorithm, keepId);
}

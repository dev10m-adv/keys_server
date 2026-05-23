import 'dotenv/config';
import { Pool } from 'pg';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const schema = readFileSync(join(__dirname, 'schema.sql'), 'utf8');

const pool = new Pool({
    user: process.env.DB_USER || 'postgres',
    host: process.env.DB_HOST || 'localhost',
    database: process.env.DB_NAME || 'secmail',
    password: process.env.DB_PASSWORD || 'postgres',
    port: Number(process.env.DB_PORT) || 5432,
    max: Number(process.env.DB_POOL_MAX) || 10,
    idleTimeoutMillis: Number(process.env.DB_POOL_IDLE_TIMEOUT_MS) || 30000,
    connectionTimeoutMillis: Number(process.env.DB_POOL_CONN_TIMEOUT_MS) || 10000,
});

pool.on('error', (err) => {
    console.error('[db] PostgreSQL pool error:', err);
});

function toPgParams(sql) {
    let index = 0;
    return sql.replace(/\?/g, () => `$${++index}`);
}

function createAdapter(queryFn) {
    return {
        prepare(sql) {
            const text = toPgParams(sql);

            return {
                async get(...params) {
                    const result = await queryFn(text, params);
                    return result.rows[0] ?? undefined;
                },
                async all(...params) {
                    const result = await queryFn(text, params);
                    return result.rows;
                },
                async run(...params) {
                    const result = await queryFn(text, params);
                    return { changes: result.rowCount ?? 0 };
                },
            };
        },

        transaction(fn) {
            return async (...args) => {
                const client = await pool.connect();
                const txDb = createAdapter((text, params) => client.query(text, params));
                try {
                    await client.query('BEGIN');
                    const result = await fn(txDb, ...args);
                    await client.query('COMMIT');
                    return result;
                } catch (err) {
                    await client.query('ROLLBACK');
                    throw err;
                } finally {
                    client.release();
                }
            };
        },
    };
}

const db = createAdapter((text, params) => pool.query(text, params));

export async function initDatabase() {
    await pool.query(schema);
}

export default db;

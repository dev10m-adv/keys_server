import 'dotenv/config';
import { Pool } from 'pg';
import { readFileSync } from 'fs';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __dirname = dirname(fileURLToPath(import.meta.url));
const schema = readFileSync(join(__dirname, 'schema.sql'), 'utf8');

const DB_USER = process.env.DB_USER || 'postgres';
const DB_HOST = process.env.DB_HOST || 'localhost';
const DB_NAME = process.env.DB_NAME || 'secmail';
const DB_PASSWORD = process.env.DB_PASSWORD || 'postgres';
const DB_PORT = Number(process.env.DB_PORT) || 5432;
const DB_POOL_MAX = Number(process.env.DB_POOL_MAX) || 10;
const DB_POOL_IDLE_TIMEOUT_MS = Number(process.env.DB_POOL_IDLE_TIMEOUT_MS) || 30000;
const DB_POOL_CONN_TIMEOUT_MS = Number(process.env.DB_POOL_CONN_TIMEOUT_MS) || 10000;

const pool = new Pool({
    user: DB_USER,
    host: DB_HOST,
    database: DB_NAME,
    password: DB_PASSWORD,
    port: DB_PORT,
    max: DB_POOL_MAX,
    idleTimeoutMillis: DB_POOL_IDLE_TIMEOUT_MS,
    connectionTimeoutMillis: DB_POOL_CONN_TIMEOUT_MS,
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

function quoteIdentifier(name) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name)) {
        throw new Error(`[db] Invalid database name: ${name}`);
    }
    return `"${name}"`;
}

async function ensureDatabaseExists() {
    const adminPool = new Pool({
        user: DB_USER,
        host: DB_HOST,
        database: process.env.DB_ADMIN_NAME || 'postgres',
        password: DB_PASSWORD,
        port: DB_PORT,
        max: 1,
        idleTimeoutMillis: DB_POOL_IDLE_TIMEOUT_MS,
        connectionTimeoutMillis: DB_POOL_CONN_TIMEOUT_MS,
    });

    try {
        const exists = await adminPool.query(
            'SELECT 1 FROM pg_database WHERE datname = $1 LIMIT 1',
            [DB_NAME]
        );

        if (exists.rowCount === 0) {
            const quotedDbName = quoteIdentifier(DB_NAME);
            await adminPool.query(`CREATE DATABASE ${quotedDbName}`);
            console.log(`[db] Created missing database: ${DB_NAME}`);
        }
    } finally {
        await adminPool.end();
    }
}

export async function initDatabase() {
    try {
        await pool.query(schema);
    } catch (err) {
        // 3D000 = invalid_catalog_name (database does not exist)
        if (err?.code !== '3D000') throw err;

        await ensureDatabaseExists();
        await pool.query(schema);
    }
}

export default db;

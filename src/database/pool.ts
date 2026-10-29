import mysql, { type Pool } from 'mysql2/promise';
import { loadConfig } from '../config/env';

const config = loadConfig();

export const pool: Pool = mysql.createPool({
host: config.database.host,
port: config.database.port,
database: config.database.name,
user: config.database.user,
password: config.database.password,
waitForConnections: true,
connectionLimit: 5,
queueLimit: 0,
enableKeepAlive: true,
});

export async function checkDatabaseConnection(): Promise<void> {
const connection = await pool.getConnection();

try {
await connection.ping();
} finally {
connection.release();
}
}

export async function closeDatabaseConnection(): Promise<void> {
await pool.end();
}

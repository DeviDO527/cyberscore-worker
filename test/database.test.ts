import { describe, it, expect, afterAll } from '@jest/globals';
import mysql from 'mysql2/promise';
import { loadConfig } from '../src/config/env';


describe('Conexión con MySQL', () => {
    let connection: mysql.Connection | undefined;

    afterAll(async () => {
        if (connection) {
            await connection.end();
        }
    });

    it('debe conectarse a la base de datos configurada', async () => {
        const config = loadConfig();

        connection = await mysql.createConnection({
          host: config.database.host,
          port: config.database.port,
          database: config.database.name,
          user: config.database.user,
          password: config.database.password,
          connectTimeout: 5000,
        });

        const [rows] = await connection.query('SELECT 1 AS resultado');

        expect(rows).toEqual([{ resultado: 1 }]);

    });
});

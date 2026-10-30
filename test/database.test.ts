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

        // Configuración necesaria para esta prueba de integración.
        if (!process.env.ALLOWED_DOMAINS?.trim()) {
            process.env.ALLOWED_DOMAINS = 'example.com';
        }

        process.env.ALLOW_ANY_PUBLIC_DOMAIN = 'false';

        const config = loadConfig();

    });
});

import { afterAll, describe, expect, it } from '@jest/globals';
import { loadConfig } from '../src/config/env';

const databaseEnvironmentKeys = [
    'NODE_ENV',
    'LOG_LEVEL',
    'DB_HOST',
    'DB_PORT',
    'DB_NAME',
    'DB_USER',
    'DB_PASSWORD',
    'ALLOWED_DOMAINS',
    'ALLOW_ANY_PUBLIC_DOMAIN',
] as const;

const originalDatabaseEnvironment = new Map(
    databaseEnvironmentKeys.map(key => [key, process.env[key]]),
);

afterAll(() => {
    for (const key of databaseEnvironmentKeys) {
        const originalValue = originalDatabaseEnvironment.get(key);

        if (originalValue === undefined) {
            delete process.env[key];
        } else {
            process.env[key] = originalValue;
        }
    }
});

describe('Configuración de conexión con MySQL', () => {
    it('carga los valores de conexión configurados', () => {
        process.env.NODE_ENV = 'test';
        process.env.LOG_LEVEL = 'silent';
        process.env.DB_HOST = 'mysql.test.invalid';
        process.env.DB_PORT = '3308';
        process.env.DB_NAME = 'cyberscore_test';
        process.env.DB_USER = 'test-user';
        process.env.DB_PASSWORD = 'test-password';
        process.env.ALLOWED_DOMAINS = 'example.com';
        process.env.ALLOW_ANY_PUBLIC_DOMAIN = 'false';

        const config = loadConfig();

        expect(config.database).toEqual({
            host: 'mysql.test.invalid',
            port: 3308,
            name: 'cyberscore_test',
            user: 'test-user',
            password: 'test-password',
        });
        expect(config.allowedDomains).toEqual(['example.com']);
    });
});

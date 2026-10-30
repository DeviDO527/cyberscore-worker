import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { loadConfig } from '../src/config/env';

describe('WorkerConfig', () => {
    const originalEnv = { ...process.env };

    beforeEach(() => {
        Object.assign(process.env, {
            NODE_ENV: 'development',
            LOG_LEVEL: 'info',
            DB_HOST: 'localhost',
            DB_PORT: '3308',
            DB_NAME: 'cyberscore_pyme_test',
            DB_USER: 'root',
            DB_PASSWORD: 'test',
            ALLOWED_DOMAINS: 'example.com, test.example.com',
            ALLOW_ANY_PUBLIC_DOMAIN: 'false',
        });
    });

    afterEach(() => {
        Object.keys(process.env).forEach(key => {
            if (!(key in originalEnv)) {
                delete process.env[key];
            }
        });

        Object.assign(process.env, originalEnv);
    });

    it('carga correctamente los dominios autorizados', () => {
        const config = loadConfig();

        expect(config.allowedDomains).toEqual([
            'example.com',
            'test.example.com',
        ]);
    });

    it('desactiva el modo demostración por defecto', () => {
        delete process.env.ALLOW_ANY_PUBLIC_DOMAIN;

        const config = loadConfig();

        expect(config.allowAnyPublicDomain).toBe(false);
    });

    it('permite el modo demostración en desarrollo', () => {
        process.env.ALLOW_ANY_PUBLIC_DOMAIN = 'true';
        delete process.env.ALLOWED_DOMAINS;

        const config = loadConfig();

        expect(config.allowAnyPublicDomain).toBe(true);
        expect(config.allowedDomains).toEqual([]);
    });

    it('rechaza el modo demostración en producción', () => {
        process.env.NODE_ENV = 'production';
        process.env.ALLOW_ANY_PUBLIC_DOMAIN = 'true';

        expect(() => loadConfig()).toThrow(
            'no puede estar habilitado en producción',
        );
    });

    it('rechaza una configuración booleana inválida', () => {
        process.env.ALLOW_ANY_PUBLIC_DOMAIN = 'yes';

        expect(() => loadConfig()).toThrow();
    });

    it('exige dominios autorizados en modo controlado', () => {
        delete process.env.ALLOWED_DOMAINS;

        expect(() => loadConfig()).toThrow();
    });

    it('elimina entradas vacías y espacios de la lista de dominios', () => {
        process.env.ALLOWED_DOMAINS =
            'example.com, , test.example.com, ';

        const config = loadConfig();

        expect(config.allowedDomains).toEqual([
            'example.com',
            'test.example.com',
        ]);
    });
});
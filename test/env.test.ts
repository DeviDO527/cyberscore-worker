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

    it('rechaza una variable obligatoria vacía', () => {
        process.env.DB_HOST = '   ';

        expect(() => loadConfig()).toThrow(
            'La variable de entorno DB_HOST es obligatoria.',
        );
    });

    it('rechaza una variable obligatoria ausente', () => {
        delete process.env.DB_PASSWORD;

        expect(() => loadConfig()).toThrow(
            'La variable de entorno DB_PASSWORD es obligatoria.',
        );
    });

    it('utiliza los valores predeterminados cuando no se configuran los parámetros', () => {
        delete process.env.DB_PORT;
        delete process.env.WORKER_POLL_INTERVAL_MS;
        delete process.env.WORKER_BATCH_SIZE;

        const config = loadConfig();

        expect(config.database.port).toBe(3308);
        expect(config.worker.pollIntervalMs).toBe(5000);
        expect(config.worker.batchSize).toBe(1);
    });

    it('utiliza el valor predeterminado cuando una variable numérica está vacía', () => {
        process.env.WORKER_BATCH_SIZE = '   ';

        const config = loadConfig();

        expect(config.worker.batchSize).toBe(1);
    });

    it.each([
        '0',
        '-1',
        '1.5',
        'abc',
        '9007199254740992',
    ])('rechaza el entero positivo inválido: %s', (value) => {
        process.env.WORKER_BATCH_SIZE = value;

        expect(() => loadConfig()).toThrow(
            'La variable WORKER_BATCH_SIZE debe ser un número entero positivo.',
        );
    });

    it('rechaza un puerto de base de datos superior a 65535', () => {
        process.env.DB_PORT = '65536';

        expect(() => loadConfig()).toThrow(
            'DB_PORT debe estar entre 1 y 65535.',
        );
    });

    it('utiliza info cuando no se configura el nivel de logging', () => {
        delete process.env.LOG_LEVEL;

        const config = loadConfig();

        expect(config.logLevel).toBe('info');
    });

    it('rechaza un nivel de logging no soportado', () => {
        process.env.LOG_LEVEL = 'verbose';

        expect(() => loadConfig()).toThrow(
            'LOG_LEVEL debe ser uno de los siguientes valores:',
        );
    });

    it('utiliza development cuando no se configura NODE_ENV', () => {
        delete process.env.NODE_ENV;

        const config = loadConfig();

        expect(config.nodeEnv).toBe('development');
    });

    it('rechaza un entorno de ejecución no soportado', () => {
        process.env.NODE_ENV = 'staging';

        expect(() => loadConfig()).toThrow(
            'NODE_ENV debe ser development, test o production.',
        );
    });

    it('utiliza false cuando la variable booleana contiene espacios', () => {
        process.env.ALLOW_ANY_PUBLIC_DOMAIN = '   ';

        const config = loadConfig();

        expect(config.allowAnyPublicDomain).toBe(false);
    });

    it('rechaza dominios con formato inválido', () => {
        process.env.ALLOWED_DOMAINS = 'https://example.com';

        expect(() => loadConfig()).toThrow(
            "El dominio 'https://example.com' de ALLOWED_DOMAINS no tiene un formato válido.",
        );
    });

    it('rechaza una lista de dominios que queda vacía después de eliminar espacios', () => {
        process.env.ALLOWED_DOMAINS = ' , , ';

        expect(() => loadConfig()).toThrow(
            'Debe configurarse al menos un dominio autorizado.',
        );
    });

    it('normaliza y elimina dominios duplicados', () => {
        process.env.ALLOWED_DOMAINS =
            'example.com, EXAMPLE.COM., test.example.com.';

        const config = loadConfig();

        expect(config.allowedDomains).toEqual([
            'example.com',
            'test.example.com',
        ]);
    });

    it('omite la API key cuando no está configurada', () => {
        delete process.env.VIRUSTOTAL_API_KEY;
        
        const config = loadConfig();
        
        expect(config.virusTotalApiKey).toBeUndefined();
    });
    
    it('omite la API key cuando contiene solamente espacios', () => {
        process.env.VIRUSTOTAL_API_KEY = '   ';
    
        const config = loadConfig();
    
        expect(config.virusTotalApiKey).toBeUndefined();
    });
    
    it('normaliza la API key configurada', () => {
        process.env.VIRUSTOTAL_API_KEY = '  test-api-key  ';
    
        const config = loadConfig();
    
        expect(config.virusTotalApiKey).toBe('test-api-key');
    });

});
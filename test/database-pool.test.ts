import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';

interface MockConnection {
    ping: jest.Mock<() => Promise<void>>;
    release: jest.Mock<() => void>;
}

interface MockPool {
    getConnection: jest.Mock<() => Promise<MockConnection>>;
    end: jest.Mock<() => Promise<void>>;
}

describe('DatabasePool', () => {
    let mockConnection: MockConnection;
    let mockPool: MockPool;
    let mockCreatePool: jest.Mock<
        (options: Record<string, unknown>) => MockPool
    >;

    let databaseModule: typeof import('../src/database/pool');

    const originalEnv = { ...process.env };

    beforeEach(() => {
        process.env.NODE_ENV = 'test';
        process.env.LOG_LEVEL = 'info';

        process.env.DB_HOST = 'localhost';
        process.env.DB_PORT = '3308';
        process.env.DB_NAME = 'cyberscore_pyme_test';
        process.env.DB_USER = 'root';
        process.env.DB_PASSWORD = 'test';

        process.env.ALLOWED_DOMAINS = 'example.com';
        process.env.ALLOW_ANY_PUBLIC_DOMAIN = 'false';

        mockConnection = {
            ping: jest.fn<() => Promise<void>>().mockResolvedValue(),
            release: jest.fn<() => void>(),
        };

        mockPool = {
            getConnection: jest.fn<() => Promise<MockConnection>>()
                .mockResolvedValue(mockConnection),

            end: jest.fn<() => Promise<void>>().mockResolvedValue(),
        };

        mockCreatePool = jest.fn<
            (options: Record<string, unknown>) => MockPool
        >().mockReturnValue(mockPool);

        jest.resetModules();

        jest.doMock('mysql2/promise', () => ({
            __esModule: true,
            default: {
                createPool: mockCreatePool,
            },
        }));

        databaseModule = require('../src/database/pool');
    });

    afterEach(() => {
        jest.dontMock('mysql2/promise');
        jest.resetModules();

        Object.keys(process.env).forEach(key => {
            if (!(key in originalEnv)) {
                delete process.env[key];
            }
        });

        Object.assign(process.env, originalEnv);
    });

    it('configura correctamente el pool de MySQL', () => {
        expect(mockCreatePool).toHaveBeenCalledWith({
            host: 'localhost',
            port: 3308,
            database: 'cyberscore_pyme_test',
            user: 'root',
            password: 'test',
            waitForConnections: true,
            connectionLimit: 5,
            queueLimit: 0,
            enableKeepAlive: true,
        });
    });

    it('comprueba correctamente la conexión con MySQL', async () => {
        await databaseModule.checkDatabaseConnection();

        expect(mockPool.getConnection).toHaveBeenCalledTimes(1);
        expect(mockConnection.ping).toHaveBeenCalledTimes(1);
        expect(mockConnection.release).toHaveBeenCalledTimes(1);
    });

    it('libera la conexión aunque falle el ping', async () => {
        mockConnection.ping.mockRejectedValue(
            new Error('Error durante ping'),
        );

        await expect(
            databaseModule.checkDatabaseConnection(),
        ).rejects.toThrow('Error durante ping');

        expect(mockConnection.release).toHaveBeenCalledTimes(1);
    });

    it('propaga errores al intentar obtener una conexión', async () => {
        mockPool.getConnection.mockRejectedValue(
            new Error('MySQL no disponible'),
        );

        await expect(
            databaseModule.checkDatabaseConnection(),
        ).rejects.toThrow('MySQL no disponible');

        expect(mockConnection.ping).not.toHaveBeenCalled();
        expect(mockConnection.release).not.toHaveBeenCalled();
    });

    it('cierra correctamente el pool de conexiones', async () => {
        await databaseModule.closeDatabaseConnection();

        expect(mockPool.end).toHaveBeenCalledTimes(1);
    });

    it('propaga errores al cerrar el pool', async () => {
        mockPool.end.mockRejectedValue(
            new Error('No fue posible cerrar MySQL'),
        );

        await expect(
            databaseModule.closeDatabaseConnection(),
        ).rejects.toThrow('No fue posible cerrar MySQL');
    });
});
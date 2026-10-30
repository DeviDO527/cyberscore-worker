import { jest, describe, it, expect, beforeEach } from '@jest/globals';
import { NetworkTargetValidator } from '../src/security/network-target-validator';

describe('NetworkTargetValidator', () => {
    let dnsMock: {
        resolve: ReturnType<typeof jest.fn>;
    };

    let validator: NetworkTargetValidator;

    beforeEach(() => {
        jest.clearAllMocks();

        dnsMock = {
            resolve: jest.fn(),
        };

        validator = new NetworkTargetValidator(
            ['example.com', 'test.example.com'],
            dnsMock,
        );
    });

    describe('Validación del dominio', () => {
        it('acepta un dominio incluido en la lista permitida', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '93.184.216.34', family: 4 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).resolves.toMatchObject({
                hostname: 'example.com',
                addresses: ['93.184.216.34'],
            });
        });

        it('rechaza dominios que no están autorizados', async () => {
            await expect(
                validator.validate('google.com'),
            ).rejects.toThrow();

            expect(dnsMock.resolve).not.toHaveBeenCalled();
        });

        it('rechaza dominios vacíos', async () => {
            await expect(
                validator.validate(''),
            ).rejects.toThrow();

            expect(dnsMock.resolve).not.toHaveBeenCalled();
        });

        it('rechaza dominios con formato inválido', async () => {
            await expect(
                validator.validate('dominio no válido'),
            ).rejects.toThrow();

            expect(dnsMock.resolve).not.toHaveBeenCalled();
        });
    });

    describe('Validación de direcciones IP', () => {
        it('rechaza direcciones IPv4 privadas', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '192.168.1.10', family: 4 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('rechaza direcciones loopback', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '127.0.0.1', family: 4 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('rechaza direcciones IPv6 locales', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '::1', family: 6 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('rechaza dominios con una combinación de IP pública y privada', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '93.184.216.34', family: 4 },
                { address: '192.168.1.10', family: 4 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('rechaza dominios que no tienen registros utilizables', async () => {
            dnsMock.resolve.mockResolvedValue([]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('propaga un error de resolución DNS', async () => {
            dnsMock.resolve.mockRejectedValue(
                new Error('DNS no disponible'),
            );

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow('DNS no disponible');
        });
    });

    describe('Normalización del dominio', () => {
        it('normaliza el dominio a minúsculas', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '93.184.216.34', family: 4 },
            ]);

            const result = await validator.validate('EXAMPLE.COM');

            expect(result.hostname).toBe('example.com');
        });

        it('rechaza dominios con protocolo HTTP', async () => {
            await expect(
                validator.validate('https://example.com'),
            ).rejects.toThrow();
        });
    });
});

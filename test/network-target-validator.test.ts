import { jest, describe, it, expect, beforeEach } from '@jest/globals';

import {
    NetworkTargetValidator,
} from '../src/security/network-target-validator';

import type {
    DnsResolver,
    ResolvedAddress,
} from '../src/security/network-target-validator';

describe('NetworkTargetValidator', () => {
    let dnsMock: {
        resolve: jest.Mock<
            (hostname: string) => Promise<ResolvedAddress[]>
        >;
    };

    let validator: NetworkTargetValidator;

    beforeEach(() => {
        jest.clearAllMocks();

        dnsMock = {
            resolve: jest.fn<
                (hostname: string) => Promise<ResolvedAddress[]>
            >(),
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

        it('rechaza dominios que no están autorizados en modo controlado', async () => {
            await expect(
                validator.validate('google.com'),
            ).rejects.toThrow('Dominio no autorizado');

            expect(dnsMock.resolve).not.toHaveBeenCalled();
        });

        it('acepta cualquier dominio público en modo demostración', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '8.8.8.8', family: 4 },
            ]);

            const demoValidator = new NetworkTargetValidator(
                [],
                dnsMock,
                { allowAnyPublicDomain: true },
            );

            await expect(
                demoValidator.validate('google.com'),
            ).resolves.toMatchObject({
                hostname: 'google.com',
                addresses: ['8.8.8.8'],
            });

            expect(dnsMock.resolve).toHaveBeenCalledWith('google.com');
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

        it('también valida el formato del dominio en modo demostración', async () => {
            const demoValidator = new NetworkTargetValidator(
                [],
                dnsMock,
                { allowAnyPublicDomain: true },
            );

            await expect(
                demoValidator.validate('https://google.com'),
            ).rejects.toThrow();

            expect(dnsMock.resolve).not.toHaveBeenCalled();
        });
    });

    describe('Validación de direcciones IPv4', () => {
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

        it('rechaza direcciones IPv4 link-local', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '169.254.10.20', family: 4 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('rechaza direcciones IPv4 de documentación', async () => {
            const reservedAddresses = [
                '192.0.2.10',
                '198.51.100.10',
                '203.0.113.10',
            ];

            for (const address of reservedAddresses) {
                dnsMock.resolve.mockResolvedValue([
                    { address, family: 4 },
                ]);

                await expect(
                    validator.validate('example.com'),
                ).rejects.toThrow();
            }
        });

        it('rechaza direcciones IPv4 de uso compartido', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '100.64.10.1', family: 4 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('rechaza direcciones IPv4 multicast y reservadas', async () => {
            for (const address of ['224.0.0.1', '240.0.0.1']) {
                dnsMock.resolve.mockResolvedValue([
                    { address, family: 4 },
                ]);

                await expect(
                    validator.validate('example.com'),
                ).rejects.toThrow();
            }
        });
    });

    describe('Validación de direcciones IPv6', () => {
        it('rechaza direcciones IPv6 loopback', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '::1', family: 6 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('rechaza direcciones IPv6 privadas ULA', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: 'fc00::1', family: 6 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('rechaza direcciones IPv6 link-local', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: 'fe80::1', family: 6 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('rechaza direcciones IPv6 multicast', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: 'ff02::1', family: 6 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('rechaza direcciones IPv6 de documentación', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '2001:db8::1', family: 6 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('rechaza direcciones IPv6 ORCHID reservadas', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '2001:20::1', family: 6 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('rechaza direcciones IPv4 mapeadas en IPv6', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '::ffff:192.168.1.10', family: 6 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('acepta una dirección IPv6 global válida', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '2001:4860:4860::8888', family: 6 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).resolves.toMatchObject({
                hostname: 'example.com',
                addresses: ['2001:4860:4860::8888'],
            });
        });
    });

    describe('Protección Anti-SSRF en modo demostración', () => {
        it('rechaza direcciones privadas aunque el dominio esté autorizado para evaluación', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '127.0.0.1', family: 4 },
            ]);

            const demoValidator = new NetworkTargetValidator(
                [],
                dnsMock,
                { allowAnyPublicDomain: true },
            );

            await expect(
                demoValidator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('rechaza dominios con una combinación de IP pública y privada', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '93.184.216.34', family: 4 },
                { address: '192.168.1.10', family: 4 },
            ]);

            const demoValidator = new NetworkTargetValidator(
                [],
                dnsMock,
                { allowAnyPublicDomain: true },
            );

            await expect(
                demoValidator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('rechaza dominios que no tienen registros utilizables', async () => {
            dnsMock.resolve.mockResolvedValue([]);

            const demoValidator = new NetworkTargetValidator(
                [],
                dnsMock,
                { allowAnyPublicDomain: true },
            );

            await expect(
                demoValidator.validate('example.com'),
            ).rejects.toThrow();
        });

        it('propaga un error de resolución DNS', async () => {
            dnsMock.resolve.mockRejectedValue(
                new Error('DNS no disponible'),
            );

            const demoValidator = new NetworkTargetValidator(
                [],
                dnsMock,
                { allowAnyPublicDomain: true },
            );

            await expect(
                demoValidator.validate('example.com'),
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

        it('acepta un dominio terminado en punto y lo normaliza', async () => {
            dnsMock.resolve.mockResolvedValue([
                { address: '93.184.216.34', family: 4 },
            ]);

            const result = await validator.validate('example.com.');

            expect(result.hostname).toBe('example.com');
            expect(dnsMock.resolve).toHaveBeenCalledWith('example.com');
        });
    });
});
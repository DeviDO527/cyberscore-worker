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
        it.each([
            { category: 'privadas', address: '192.168.1.10' },
            { category: 'loopback', address: '127.0.0.1' },
            { category: 'link-local', address: '169.254.10.20' },
            { category: 'de documentación', address: '192.0.2.10' },
            { category: 'de documentación', address: '198.51.100.10' },
            { category: 'de documentación', address: '203.0.113.10' },
        ])('rechaza direcciones IPv4 $category ($address)', async ({ address }) => {
            dnsMock.resolve.mockResolvedValue([
                { address, family: 4 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
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

        it.each([
            { address: '0.0.0.1' },
            { address: '10.0.0.1' },
            { address: '100.64.0.1' },
            { address: '127.0.0.1' },
            { address: '169.254.0.1' },
            { address: '172.16.0.1' },
            { address: '192.0.0.1' },
            { address: '192.0.2.1' },
            { address: '192.88.99.1' },
            { address: '192.168.0.1' },
            { address: '198.18.0.1' },
            { address: '198.51.100.1' },
            { address: '203.0.113.1' },
            { address: '224.0.0.1' },
            { address: '240.0.0.1' },
        ])('rechaza el bloque IPv4 especial $address', async ({ address }) => {
            dnsMock.resolve.mockResolvedValue([
                { address, family: 4 },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow();
        });
    });

    describe('Validación de direcciones IPv6', () => {
        it.each([
            { category: 'loopback', address: '::1' },
            { category: 'privada ULA', address: 'fc00::1' },
            { category: 'link-local', address: 'fe80::1' },
            { category: 'multicast', address: 'ff02::1' },
            { category: 'de documentación', address: '2001:db8::1' },
            { category: 'ORCHID reservada', address: '2001:20::1' },
            { category: 'de transición', address: '2002::1' },
            { category: 'especial reservada', address: '3fff::1' },
        ])('rechaza una IPv6 $category ($address)', async ({ address }) => {
            dnsMock.resolve.mockResolvedValue([
                { address, family: 6 },
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

    describe('Casos adicionales de validación y parsing', () => {

        type ValidatorInternals = {
            isPublicIP(address: string): boolean;

            isIPv4InCidr(
                address: string,
                network: string,
                prefix: number,
            ): boolean;

            ipv4ToNumber(address: string): number | null;

            isIPv6InCidr(
                address: string,
                network: string,
                prefix: number,
            ): boolean;

            parseIPv6(address: string): number[] | null;
        };

        const getInternals = (): ValidatorInternals =>
            validator as unknown as ValidatorInternals;

        // =================================================
        // VALIDACIÓN DEL DOMINIO Y DNS
        // =================================================

        it('rechaza dominios superiores a 253 caracteres', async () => {

            const longDomain = [
                'a'.repeat(63),
                'b'.repeat(63),
                'c'.repeat(63),
                'd'.repeat(63),
            ].join('.');

            await expect(
                validator.validate(longDomain),
            ).rejects.toThrow('Formato de dominio inválido');

            expect(dnsMock.resolve).not.toHaveBeenCalled();
        });

        it('rechaza direcciones DNS que no corresponden a una IP válida', async () => {

            dnsMock.resolve.mockResolvedValue([
                {
                    address: 'not-an-ip',
                    family: 4,
                },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow('Dirección IP no permitida');

        });

        it('rechaza direcciones cuya familia DNS no coincide con su formato', async () => {

            dnsMock.resolve.mockResolvedValue([
                {
                    address: '93.184.216.34',
                    family: 6,
                },
            ]);

            await expect(
                validator.validate('example.com'),
            ).rejects.toThrow('Dirección IP no permitida');
        });

        // =================================================
        // VALIDACIÓN INTERNA IPv4
        // =================================================

        it('rechaza direcciones que no pertenecen a IPv4 ni IPv6', () => {

            expect(
                getInternals().isPublicIP('not-an-ip'),
            ).toBe(false);
        });

        it('evalúa correctamente una máscara IPv4 de prefijo cero', () => {

            expect(
                getInternals().isIPv4InCidr(
                    '93.184.216.34',
                    '0.0.0.0',
                    0,
                ),
            ).toBe(true);
        });

        it('rechaza una dirección inválida al comprobar un rango IPv4', () => {

            expect(
                getInternals().isIPv4InCidr(
                    'not-an-ip',
                    '0.0.0.0',
                    24,
                ),
            ).toBe(false);
        });

        it('rechaza una entrada que no sea una dirección IPv4 al convertirla', () => {

            expect(
                getInternals().ipv4ToNumber('not-an-ip'),
            ).toBeNull();
        });

        // =================================================
        // VALIDACIÓN INTERNA IPv6
        // =================================================

        it('rechaza una dirección IPv6 que no puede analizarse al evaluar un CIDR', () => {

            expect(
                getInternals().isIPv6InCidr(
                    'invalid-ip',
                    '2000::',
                    3,
                ),
            ).toBe(false);
        });

        it.each([
            {
                description: 'un identificador de interfaz',
                address: '2001:4860::8888%eth0',
            },
            {
                description: 'una dirección IPv4 sin representación IPv6',
                address: '192.0.2.1',
            },
            {
                description: 'una dirección IPv4 embebida inválida',
                address: '2001::192.0.2.999',
            },
            {
                description: 'múltiples operadores de compresión',
                address: '2001::1::2',
            },
            {
                description: 'una compresión que no omite grupos',
                address: '1:2:3:4:5:6:7:8::',
            },
            {
                description: 'una dirección con menos de ocho grupos',
                address: '1:2:3:4:5:6:7',
            },
            {
                description: 'un grupo hexadecimal inválido',
                address: '2001:4860:4860:0:0:0:zzzz:8888',
            },
        ])(
            'rechaza IPv6 con $description',
            ({ address }) => {

                expect(
                    getInternals().parseIPv6(address),
                ).toBeNull();
            },
        );

        it('procesa correctamente una IPv6 completa con IPv4 embebida', () => {

            const result = getInternals().parseIPv6(
                '2001:4860:0:0:0:0:192.0.2.1',
            );

            expect(result).not.toBeNull();
            expect(result).toHaveLength(8);

            expect(result?.slice(-2)).toEqual([
                0xc000,
                0x0201,
            ]);
        });

    });

    describe('Resolver DNS predeterminado', () => {

       it('utiliza lookup con todos los registros y conserva el orden DNS', async () => {

            const lookupMock = jest.fn<
            (
                hostname: string,
                options: {
                    all: true;
                    verbatim: true;
                },
            ) => Promise<Array<{
                address: string;
                family: number;
            }>>
            >().mockResolvedValue([
                {
                    address: '93.184.216.34',
                    family: 4,
                },
            ]);

           jest.resetModules();

           jest.doMock('node:dns/promises', () => ({
               lookup: lookupMock,
           }));

           try {

               const module = require(
                   '../src/security/network-target-validator',
               ) as typeof import(
                   '../src/security/network-target-validator'
               );

               const defaultValidator =
                   new module.NetworkTargetValidator([
                       'example.com',
                   ]);

               const result = await defaultValidator.validate(
                   'example.com',
               );

               expect(result.addresses).toEqual([
                   '93.184.216.34',
               ]);

               expect(lookupMock).toHaveBeenCalledWith(
                   'example.com',
                   {
                       all: true,
                       verbatim: true,
                   },
               );

           } finally {

               jest.dontMock('node:dns/promises');
               jest.resetModules();

           }
       });

    });

    describe('Validación defensiva de octetos IPv4', () => {

        it('rechaza componentes IPv4 inválidos aunque isIP los clasifique como IPv4', () => {

            const realIsIP = require('node:net').isIP as (
                address: string,
            ) => number;

            const mockedIsIP = jest.fn<
                (address: string) => number
            >();

            mockedIsIP.mockImplementation((address) => {

                if (
                    address === '1.2.3' ||
                    address === '1.2.3.999'
                ) {
                    return 4;
                }

                return realIsIP(address);
            });

            jest.resetModules();

            jest.doMock('node:net', () => ({
                isIP: mockedIsIP,
            }));

            try {

                const module = require(
                    '../src/security/network-target-validator',
                ) as typeof import(
                    '../src/security/network-target-validator'
                );

                const isolatedValidator =
                    new module.NetworkTargetValidator(
                        ['example.com'],
                        dnsMock,
                    );

                const internals = isolatedValidator as unknown as {
                    ipv4ToNumber(address: string): number | null;
                };

                expect(
                    internals.ipv4ToNumber('1.2.3'),
                ).toBeNull();

                expect(
                    internals.ipv4ToNumber('1.2.3.999'),
                ).toBeNull();

            } finally {

                jest.dontMock('node:net');
                jest.resetModules();

            }
        });

    });

});

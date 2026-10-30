import { beforeEach, describe, expect, it, jest } from '@jest/globals';

import {
    TlsInspector,
    TlsInspection,
} from '../src/services/tls-inspector';

import { ValidatedTarget } from '../src/security/network-target-validator';

describe('TlsInspector', () => {
    let tlsMock: {
        inspect: jest.Mock<
            (target: ValidatedTarget) => Promise<TlsInspection>
        >;
    };

    let validatorMock: {
        validate: jest.Mock<
            (domain: string) => Promise<ValidatedTarget>
        >;
    };

    let inspector: TlsInspector;

    const validatedTarget: ValidatedTarget = {
        hostname: 'example.com',
        addresses: ['93.184.216.34'],
    };

    beforeEach(() => {
        jest.clearAllMocks();

        tlsMock = {
            inspect: jest.fn<
                (target: ValidatedTarget) => Promise<TlsInspection>
            >(),
        };

        validatorMock = {
            validate: jest.fn<
                (domain: string) => Promise<ValidatedTarget>
            >(),
        };

        validatorMock.validate.mockResolvedValue(validatedTarget);

        inspector = new TlsInspector(validatorMock, tlsMock);
    });

    it('obtiene la información de la conexión TLS', async () => {
        tlsMock.inspect.mockResolvedValue({
            authorized: true,
            protocol: 'TLSv1.3',
            validFrom: 'Jan 01 00:00:00 2026 GMT',
            validTo: 'Jan 01 00:00:00 2027 GMT',
            subject: { CN: 'example.com' },
            issuer: { CN: 'Example CA' },
        });

        await inspector.inspect('example.com');

        expect(tlsMock.inspect).toHaveBeenCalledWith(validatedTarget);
    });

    it('devuelve los datos del certificado y del protocolo', async () => {
        const connection: TlsInspection = {
            authorized: true,
            protocol: 'TLSv1.3',
            validFrom: 'Jan 01 00:00:00 2026 GMT',
            validTo: 'Jan 01 00:00:00 2027 GMT',
            subject: { CN: 'example.com' },
            issuer: { CN: 'Example CA' },
        };

        tlsMock.inspect.mockResolvedValue(connection);

        const result = await inspector.inspect('example.com');

        expect(result).toEqual(connection);
    });

    it('conserva el error de autorización del certificado', async () => {
        tlsMock.inspect.mockResolvedValue({
            authorized: false,
            authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
            protocol: 'TLSv1.2',
            validFrom: 'Jan 01 00:00:00 2026 GMT',
            validTo: 'Jan 01 00:00:00 2027 GMT',
            subject: { CN: 'example.com' },
            issuer: { CN: 'Unknown CA' },
        });

        const result = await inspector.inspect('example.com');

        expect(result.authorized).toBe(false);
        expect(result.authorizationError).toBe(
            'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
        );
    });

    it('rechaza un dominio vacío sin iniciar la inspección', async () => {
        await expect(inspector.inspect('')).rejects.toThrow();

        expect(validatorMock.validate).not.toHaveBeenCalled();
        expect(tlsMock.inspect).not.toHaveBeenCalled();
    });

    it('rechaza un dominio con formato inválido', async () => {
        await expect(
            inspector.inspect('esto no es un dominio'),
        ).rejects.toThrow();

        expect(validatorMock.validate).not.toHaveBeenCalled();
        expect(tlsMock.inspect).not.toHaveBeenCalled();
    });

    it('propaga los errores inesperados de la conexión TLS', async () => {
        tlsMock.inspect.mockRejectedValue(
            new Error('No fue posible establecer la conexión TLS'),
        );

        await expect(
            inspector.inspect('example.com'),
        ).rejects.toThrow(
            'No fue posible establecer la conexión TLS',
        );
    });

    it('mantiene el hostname normalizado al consultar el inspector', async () => {
        tlsMock.inspect.mockResolvedValue({
            authorized: true,
            protocol: 'TLSv1.3',
            validFrom: 'Jan 01 00:00:00 2026 GMT',
            validTo: 'Jan 01 00:00:00 2027 GMT',
            subject: { CN: 'example.com' },
            issuer: { CN: 'Example CA' },
        });

        await inspector.inspect('  EXAMPLE.COM  ');

        expect(validatorMock.validate).toHaveBeenCalledWith('EXAMPLE.COM');
        expect(tlsMock.inspect).toHaveBeenCalledWith(validatedTarget);
    });

    it('no inicia conexiones cuando el dominio tiene formato inválido', async () => {
        await expect(
            inspector.inspect('https://example.com'),
        ).rejects.toThrow();

        expect(validatorMock.validate).not.toHaveBeenCalled();
        expect(tlsMock.inspect).not.toHaveBeenCalled();
    });

    it('valida el dominio antes de iniciar la conexión TLS', async () => {
        await inspector.inspect('example.com');

        expect(validatorMock.validate).toHaveBeenCalledWith('example.com');
        expect(tlsMock.inspect).toHaveBeenCalledWith(validatedTarget);

        expect(validatorMock.validate.mock.invocationCallOrder[0]!)
            .toBeLessThan(tlsMock.inspect.mock.invocationCallOrder[0]!);
    });

    it('no inicia conexiones cuando falla la validación del dominio', async () => {
        validatorMock.validate.mockRejectedValue(
            new Error('Dominio no autorizado: example.com'),
        );

        await expect(
            inspector.inspect('example.com'),
        ).rejects.toThrow('Dominio no autorizado');

        expect(tlsMock.inspect).not.toHaveBeenCalled();
    });

    it('rechaza una validación que no devuelve direcciones IP', async () => {
        validatorMock.validate.mockResolvedValue({
            hostname: 'example.com',
            addresses: [],
        });

        await expect(
            inspector.inspect('example.com'),
        ).rejects.toThrow();

        expect(tlsMock.inspect).not.toHaveBeenCalled();
    });
});
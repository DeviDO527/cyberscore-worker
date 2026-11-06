import { EventEmitter } from 'node:events';
import tls from 'node:tls';

import type { TLSSocket } from 'node:tls';

import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';

import {
    TlsInspector,
} from '../src/services/tls-inspector';

import type {
    ValidatedTarget,
} from '../src/security/network-target-validator';

type FakeTlsSocket = EventEmitter & {
    setTimeout: jest.Mock<(milliseconds: number) => void>;
    destroy: jest.Mock<() => void>;
    end: jest.Mock<() => void>;

    getPeerCertificate: jest.Mock<
        () => Record<string, unknown>
    >;

    getProtocol: jest.Mock<
        () => string | null
    >;

    authorized: boolean;
    authorizationError: Error | string | undefined;
};

describe('NodeTlsInspector', () => {

    let inspector: TlsInspector;

    let fakeSocket: FakeTlsSocket;

    const validatedTarget: ValidatedTarget = {
        hostname: 'example.com',
        addresses: ['93.184.216.34'],
    };

    const validatorMock = {
        validate: jest.fn<
            (domain: string) => Promise<ValidatedTarget>
        >(),
    };

    const certificate = {
        valid_from: 'Jan 01 00:00:00 2026 GMT',
        valid_to: 'Jan 01 00:00:00 2027 GMT',
        subject: {
            CN: 'example.com',
        },
        issuer: {
            CN: 'Example CA',
        },
    };

    beforeEach(() => {
        jest.clearAllMocks();

        validatorMock.validate.mockResolvedValue(
            validatedTarget,
        );

        inspector = new TlsInspector(validatorMock);

        const emitter = new EventEmitter();

        fakeSocket = Object.assign(emitter, {

            setTimeout: jest.fn<
                (milliseconds: number) => void
            >(),

            destroy: jest.fn<() => void>(),

            end: jest.fn<() => void>(),

            getPeerCertificate: jest.fn<
                () => Record<string, unknown>
            >().mockReturnValue(certificate),

            getProtocol: jest.fn<
                () => string | null
            >().mockReturnValue('TLSv1.3'),

            authorized: true,

            authorizationError: undefined,
        });

        jest.spyOn(tls, 'connect').mockImplementation(
            (() =>
                fakeSocket as unknown as TLSSocket
            ) as typeof tls.connect,
        );
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    /**
     * Espera la validación asíncrona del dominio
     * y comprueba que se inició la conexión TLS.
     */
    async function startInspection(): Promise<{
        promise: ReturnType<typeof inspector.inspect>;
    }> {

        const promise = inspector.inspect('example.com');

        await Promise.resolve();

        expect(tls.connect).toHaveBeenCalledTimes(1);

        expect(fakeSocket.setTimeout).toHaveBeenCalledWith(
            10_000,
        );

        return { promise };
    }

    it('establece la conexión TLS utilizando la IP validada y SNI original', async () => {

        const { promise } = await startInspection();

        expect(tls.connect).toHaveBeenCalledWith(
            expect.objectContaining({
                host: '93.184.216.34',
                port: 443,
                servername: 'example.com',
                rejectUnauthorized: false,
            }),
        );

        fakeSocket.emit('secureConnect');

        const result = await promise;

        expect(result).toEqual({
            authorized: true,
            protocol: 'TLSv1.3',
            validFrom: certificate.valid_from,
            validTo: certificate.valid_to,
            subject: certificate.subject,
            issuer: certificate.issuer,
        });

        expect(fakeSocket.end).toHaveBeenCalledTimes(1);
        expect(fakeSocket.destroy).not.toHaveBeenCalled();
    });

    it('conserva los errores de autorización del certificado', async () => {

        fakeSocket.authorized = false;

        fakeSocket.authorizationError =
            'UNABLE_TO_VERIFY_LEAF_SIGNATURE';

        const { promise } = await startInspection();

        fakeSocket.emit('secureConnect');

        const result = await promise;

        expect(result.authorized).toBe(false);

        expect(result.authorizationError).toBe(
            'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
        );
    });

    it('utiliza unknown cuando no se puede obtener el protocolo TLS', async () => {

        fakeSocket.getProtocol.mockReturnValue(null);

        const { promise } = await startInspection();

        fakeSocket.emit('secureConnect');

        const result = await promise;

        expect(result.protocol).toBe('unknown');
    });

    it('rechaza conexiones cuyo servidor no presenta certificado', async () => {

        fakeSocket.getPeerCertificate.mockReturnValue({});

        const { promise } = await startInspection();

        fakeSocket.emit('secureConnect');

        await expect(promise).rejects.toThrow(
            'El servidor no presentó un certificado TLS.',
        );

        expect(fakeSocket.destroy).toHaveBeenCalledTimes(1);
        expect(fakeSocket.end).not.toHaveBeenCalled();
    });

    it('propaga errores durante la lectura del certificado', async () => {

        fakeSocket.getPeerCertificate.mockImplementation(() => {
            throw new Error('Error al leer el certificado');
        });

        const { promise } = await startInspection();

        fakeSocket.emit('secureConnect');

        await expect(promise).rejects.toThrow(
            'Error al leer el certificado',
        );

        expect(fakeSocket.destroy).toHaveBeenCalledTimes(1);
    });

    it('rechaza la conexión cuando se agota el tiempo de espera', async () => {

        const { promise } = await startInspection();

        fakeSocket.emit('timeout');

        await expect(promise).rejects.toThrow(
            'Tiempo de espera agotado durante la conexión TLS.',
        );

        expect(fakeSocket.destroy).toHaveBeenCalledTimes(1);
    });

    it('propaga los errores del socket TLS', async () => {

        const { promise } = await startInspection();

        fakeSocket.emit(
            'error',
            new Error('Conexión TLS rechazada'),
        );

        await expect(promise).rejects.toThrow(
            'Conexión TLS rechazada',
        );

        expect(fakeSocket.destroy).toHaveBeenCalledTimes(1);
    });

    it('rechaza una dirección IP validada vacía', async () => {

        validatorMock.validate.mockResolvedValue({
            hostname: 'example.com',
            addresses: [''],
        });

        await expect(
            inspector.inspect('example.com'),
        ).rejects.toThrow(
            'No existe una dirección IP validada para conectar.',
        );

        expect(tls.connect).not.toHaveBeenCalled();
    });

    it('no vuelve a procesar eventos después de resolver un timeout', async () => {

        const { promise } = await startInspection();

        fakeSocket.emit('timeout');

        await expect(promise).rejects.toThrow();

        fakeSocket.emit(
            'error',
            new Error('Error posterior al timeout'),
        );

        expect(fakeSocket.destroy).toHaveBeenCalledTimes(1);
    });

    it('ignora eventos secureConnect posteriores a un error', async () => {

        const { promise } = await startInspection();

        fakeSocket.emit(
            'error',
            new Error('Conexión interrumpida'),
        );

        await expect(promise).rejects.toThrow();

        fakeSocket.emit('secureConnect');

        expect(fakeSocket.getPeerCertificate).not.toHaveBeenCalled();
        expect(fakeSocket.end).not.toHaveBeenCalled();
    });

    it('utiliza valores predeterminados cuando faltan campos del certificado', async () => {

        fakeSocket.getPeerCertificate.mockReturnValue({
            valid_from: undefined,
            valid_to: undefined,
            subject: undefined,
            issuer: undefined,
        });

        const { promise } = await startInspection();

        fakeSocket.emit('secureConnect');

        const result = await promise;

        expect(result).toMatchObject({
            authorized: true,
            protocol: 'TLSv1.3',
            validFrom: '',
            validTo: '',
            subject: {},
            issuer: {},
        });

        expect(fakeSocket.end).toHaveBeenCalledTimes(1);
    });

    it('maneja errores desconocidos durante la inspección del certificado', async () => {

        fakeSocket.getPeerCertificate.mockImplementation(() => {
            throw 'Error no identificado';
        });

        const { promise } = await startInspection();

        fakeSocket.emit('secureConnect');

        await expect(promise).rejects.toThrow(
            'Error desconocido durante la inspección TLS.',
        );

        expect(fakeSocket.destroy).toHaveBeenCalledTimes(1);
    });

});
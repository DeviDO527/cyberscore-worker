import { EventEmitter } from 'node:events';

import https from 'node:https';

import type {
    ClientRequest,
    IncomingMessage,
    RequestOptions,
} from 'node:http';

import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';

import {
    HttpInspector,
    HttpInspection,
} from '../src/services/http-inspector';

import type {
    ValidatedTarget,
} from '../src/security/network-target-validator';

type FakeRequest = EventEmitter & {
    end: jest.Mock<() => void>;
    destroy: jest.Mock<(error?: Error) => void>;
};

describe('NodeHttpInspector', () => {

    let inspector: HttpInspector;

    let fakeRequest: FakeRequest;

    let requestOptions: RequestOptions | undefined;

    let responseHandler:
        ((response: IncomingMessage) => void) | undefined;

    const validatedTarget: ValidatedTarget = {
        hostname: 'example.com',
        addresses: ['93.184.216.34'],
    };

    const validatorMock = {
        validate: jest.fn<
            (domain: string) => Promise<ValidatedTarget>
        >(),
    };

    beforeEach(() => {
        jest.clearAllMocks();

        requestOptions = undefined;
        responseHandler = undefined;

        validatorMock.validate.mockResolvedValue(
            validatedTarget,
        );

        inspector = new HttpInspector(validatorMock);

        const emitter = new EventEmitter();

        const destroy = jest.fn<(error?: Error) => void>();

        destroy.mockImplementation((error) => {
            if (error) {
                queueMicrotask(() => {
                    emitter.emit('error', error);
                });
            }
        });

        fakeRequest = Object.assign(emitter, {
            end: jest.fn<() => void>(),
            destroy,
        });

        jest.spyOn(https, 'request').mockImplementation(((
            options: RequestOptions,
            callback?: (response: IncomingMessage) => void,
        ) => {
            requestOptions = options;
            responseHandler = callback;

            return fakeRequest as unknown as ClientRequest;

        }) as unknown as typeof https.request);
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

    /**
     * Inicia la inspección y espera a que termine
     * la validación asíncrona del dominio.
     *
     * No esperamos la respuesta HTTP: únicamente
     * necesitamos que se registre la petición.
     */
    async function startInspection(): Promise<{
        promise: Promise<HttpInspection>;
    }> {

        const promise = inspector.inspect('example.com');

        await Promise.resolve();

        expect(https.request).toHaveBeenCalledTimes(1);

        return { promise };
    }

    function simulateResponse(
        statusCode?: number,
        headers: Record<string, string> = {},
    ): void {

        const response = {
            statusCode,
            headers,
            resume: jest.fn(),
        } as unknown as IncomingMessage;

        if (!responseHandler) {
            throw new Error(
                'No se registró el callback HTTP.',
            );
        }

        responseHandler(response);
    }

    // =================================================
    // RESPUESTAS HTTP
    // =================================================

    it('realiza la petición HTTPS utilizando la IP validada', async () => {

        const { promise } = await startInspection();

        simulateResponse(200, {
            'content-type': 'text/html',
        });

        const result = await promise;

        expect(requestOptions).toMatchObject({
            hostname: '93.184.216.34',
            port: 443,
            servername: 'example.com',
            path: '/',
            method: 'HEAD',
            timeout: 10_000,
            headers: {
                Host: 'example.com',
                'User-Agent': 'CyberScore-PYME/1.0',
            },
        });

        expect(result.statusCode).toBe(200);

        expect(result.headers).toEqual({
            'content-type': 'text/html',
        });

        expect(fakeRequest.end).toHaveBeenCalledTimes(1);
    });

    it('utiliza 0 cuando la respuesta no contiene código HTTP', async () => {

        const { promise } = await startInspection();

        simulateResponse(undefined, {});

        const result = await promise;

        expect(result.statusCode).toBe(0);
    });

    it('conserva las cabeceras recibidas del servidor', async () => {

        const headers = {
            'content-type': 'text/html',
            'strict-transport-security': 'max-age=31536000',
            'x-content-type-options': 'nosniff',
        };

        const { promise } = await startInspection();

        simulateResponse(200, headers);

        const result = await promise;

        expect(result.headers).toEqual(headers);
    });

    // =================================================
    // ERRORES Y TIMEOUT
    // =================================================

    it('rechaza la petición cuando se agota el tiempo de espera', async () => {

        const { promise } = await startInspection();

        fakeRequest.emit('timeout');

        await expect(promise).rejects.toThrow(
            'Tiempo de espera agotado durante la petición HTTP.',
        );

        expect(fakeRequest.destroy).toHaveBeenCalledWith(
            expect.any(Error),
        );
    });

    it('propaga los errores de conexión HTTP', async () => {

        const { promise } = await startInspection();

        fakeRequest.emit(
            'error',
            new Error('Conexión rechazada'),
        );

        await expect(promise).rejects.toThrow(
            'Conexión rechazada',
        );
    });

    // =================================================
    // VALIDACIÓN DEL DESTINO
    // =================================================

    it('rechaza una dirección IP vacía', async () => {

        validatorMock.validate.mockResolvedValue({
            hostname: 'example.com',
            addresses: [''],
        });

        await expect(
            inspector.inspect('example.com'),
        ).rejects.toThrow(
            'No existe una dirección IP validada para conectar.',
        );

        expect(https.request).not.toHaveBeenCalled();
    });
});
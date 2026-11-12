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

        validatorMock.validate.mockResolvedValue(validatedTarget);

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

        const requestMock = ((
            options: RequestOptions,
            callback?: (response: IncomingMessage) => void,
        ) => {
            requestOptions = options;
            responseHandler = callback;

            return fakeRequest as unknown as ClientRequest;
        }) as unknown as typeof https.request;

        jest.spyOn(https, 'request').mockImplementation(requestMock);
    });

    afterEach(() => {
        jest.restoreAllMocks();
    });

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
        headers: Record<string, string | string[]> = {},
    ): void {
        const response = {
            statusCode,
            headers,
            resume: jest.fn(),
        } as unknown as IncomingMessage;

        if (!responseHandler) {
            throw new Error('No se registró el callback HTTP.');
        }

        responseHandler(response);
    }

    it('realiza una petición HTTPS GET utilizando la IP validada', async () => {
        const { promise } = await startInspection();

        simulateResponse(200, {
            'content-type': 'text/html',
            server: 'nginx',
        });

        const result = await promise;

        expect(requestOptions).toMatchObject({
            hostname: '93.184.216.34',
            port: 443,
            servername: 'example.com',
            path: '/',
            method: 'GET',
            timeout: 10_000,
            headers: {
                Host: 'example.com',
                'User-Agent': 'CyberScore-PYME/1.0',
            },
        });

        expect(result).toEqual({
            statusCode: 200,
            headers: {
                'content-type': 'text/html',
                server: 'nginx',
            },
            url: 'https://example.com/',
            usesHttps: true,
            server: 'nginx',
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

    it('detecta el servidor a partir de la cabecera Server', async () => {
        const { promise } = await startInspection();

        simulateResponse(200, {
            server: 'cloudflare',
        });

        const result = await promise;

        expect(result.server).toBe('cloudflare');
    });

    it('usa el primer valor cuando la cabecera Server contiene un arreglo', async () => {
        const { promise } = await startInspection();

        simulateResponse(200, {
            server: ['nginx', 'ignored'],
        });

        const result = await promise;

        expect(result.server).toBe('nginx');
    });

    it('devuelve null cuando el servidor no expone la cabecera Server', async () => {
        const { promise } = await startInspection();

        simulateResponse(200, {});

        const result = await promise;

        expect(result.server).toBeNull();
    });

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

    it('devuelve null si la cabecera Server es una lista vacía', async () => {
        const { promise } = await startInspection();

        simulateResponse(200, { server: [] });

        await expect(promise).resolves.toMatchObject({ server: null });
    });
});
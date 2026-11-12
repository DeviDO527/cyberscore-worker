import { beforeEach, describe, expect, it, jest } from '@jest/globals';

import {
    HttpInspector,
    HttpInspection,
} from '../src/services/http-inspector';

import { ValidatedTarget } from '../src/security/network-target-validator';

describe('HttpInspector', () => {
    let httpMock: {
        inspect: jest.Mock<
            (target: ValidatedTarget) => Promise<HttpInspection>
        >;
    };

    let validatorMock: {
        validate: jest.Mock<
            (domain: string) => Promise<ValidatedTarget>
        >;
    };

    let inspector: HttpInspector;

    const validatedTarget: ValidatedTarget = {
        hostname: 'example.com',
        addresses: ['93.184.216.34'],
    };

    const response: HttpInspection = {
        statusCode: 200,
        headers: {
            'content-type': 'text/html',
            'x-content-type-options': 'nosniff',
        },
        url: 'https://example.com/',
        usesHttps: true,
        server: 'nginx',
    };

    beforeEach(() => {
        jest.clearAllMocks();

        httpMock = {
            inspect: jest.fn<
                (target: ValidatedTarget) => Promise<HttpInspection>
            >(),
        };

        validatorMock = {
            validate: jest.fn<
                (domain: string) => Promise<ValidatedTarget>
            >(),
        };

        validatorMock.validate.mockResolvedValue(validatedTarget);

        inspector = new HttpInspector(validatorMock, httpMock);
    });

    it('consulta la información HTTP del dominio', async () => {
        httpMock.inspect.mockResolvedValue(response);

        await inspector.inspect('example.com');

        expect(httpMock.inspect).toHaveBeenCalledWith(validatedTarget);
    });

    it('devuelve la información enriquecida recibida', async () => {
        httpMock.inspect.mockResolvedValue(response);

        const result = await inspector.inspect('example.com');

        expect(result).toEqual(response);
    });

    it('rechaza un dominio vacío sin consultar HTTP', async () => {
        await expect(inspector.inspect('')).rejects.toThrow();

        expect(validatorMock.validate).not.toHaveBeenCalled();
        expect(httpMock.inspect).not.toHaveBeenCalled();
    });

    it('rechaza un dominio con formato inválido', async () => {
        await expect(
            inspector.inspect('esto no es un dominio'),
        ).rejects.toThrow();

        expect(validatorMock.validate).not.toHaveBeenCalled();
        expect(httpMock.inspect).not.toHaveBeenCalled();
    });

    it('propaga los errores inesperados de la petición HTTP', async () => {
        httpMock.inspect.mockRejectedValue(
            new Error('No fue posible consultar el servidor HTTP'),
        );

        await expect(
            inspector.inspect('example.com'),
        ).rejects.toThrow(
            'No fue posible consultar el servidor HTTP',
        );
    });

    it('conserva una respuesta HTTP aunque el servidor devuelva un error', async () => {
        httpMock.inspect.mockResolvedValue({
            ...response,
            statusCode: 503,
        });

        const result = await inspector.inspect('example.com');

        expect(result.statusCode).toBe(503);
        expect(result.headers).toEqual(response.headers);
        expect(result.server).toBe('nginx');
    });

    it('mantiene el hostname normalizado al consultar el inspector', async () => {
        httpMock.inspect.mockResolvedValue(response);

        await inspector.inspect('  EXAMPLE.COM  ');

        expect(validatorMock.validate).toHaveBeenCalledWith('EXAMPLE.COM');
        expect(httpMock.inspect).toHaveBeenCalledWith(validatedTarget);
    });

    it('no realiza conexiones cuando el dominio tiene formato inválido', async () => {
        await expect(
            inspector.inspect('https://example.com'),
        ).rejects.toThrow();

        expect(validatorMock.validate).not.toHaveBeenCalled();
        expect(httpMock.inspect).not.toHaveBeenCalled();
    });

    it('valida el dominio antes de realizar la conexión HTTP', async () => {
        httpMock.inspect.mockResolvedValue(response);

        await inspector.inspect('example.com');

        expect(validatorMock.validate).toHaveBeenCalledWith('example.com');
        expect(httpMock.inspect).toHaveBeenCalledWith(validatedTarget);

        expect(validatorMock.validate.mock.invocationCallOrder[0]!)
            .toBeLessThan(httpMock.inspect.mock.invocationCallOrder[0]!);
    });

    it('no realiza conexiones cuando falla la validación del dominio', async () => {
        validatorMock.validate.mockRejectedValue(
            new Error('Dominio no autorizado: example.com'),
        );

        await expect(
            inspector.inspect('example.com'),
        ).rejects.toThrow('Dominio no autorizado');

        expect(httpMock.inspect).not.toHaveBeenCalled();
    });

    it('rechaza una validación que no devuelve direcciones IP', async () => {
        validatorMock.validate.mockResolvedValue({
            hostname: 'example.com',
            addresses: [],
        });

        await expect(
            inspector.inspect('example.com'),
        ).rejects.toThrow();

        expect(httpMock.inspect).not.toHaveBeenCalled();
    });
});
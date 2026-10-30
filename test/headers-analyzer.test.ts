import { beforeEach, describe, expect, it, jest } from '@jest/globals';

import { HeadersAnalyzer } from '../src/security/headers-analyzer';

describe('HeadersAnalyzer', () => {
    let httpMock: {
        inspect: ReturnType<typeof jest.fn>;
    };

    let analyzer: HeadersAnalyzer;

    beforeEach(() => {
        jest.clearAllMocks();

        httpMock = {
            inspect: jest.fn(),
        };

        analyzer = new HeadersAnalyzer(httpMock);
    });

    it('consulta las cabeceras HTTP del dominio', async () => {
        httpMock.inspect.mockResolvedValue({
            statusCode: 200,
            headers: {
                'strict-transport-security': 'max-age=31536000',
                'content-security-policy': "default-src 'self'",
                'x-content-type-options': 'nosniff',
                'x-frame-options': 'DENY',
                'referrer-policy': 'no-referrer',
            },
        });

        await analyzer.analyze('example.com');

        expect(httpMock.inspect).toHaveBeenCalledWith('example.com');
    });

    it('devuelve las cabeceras recopiladas', async () => {
        const headers = {
            'strict-transport-security': 'max-age=31536000',
            'content-security-policy': "default-src 'self'",
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY',
            'referrer-policy': 'no-referrer',
        };

        httpMock.inspect.mockResolvedValue({
            statusCode: 200,
            headers,
        });

        const result = await analyzer.analyze('example.com');

        expect(result.status).toBe('completed');
        expect(result.statusCode).toBe(200);
        expect(result.headers).toEqual(headers);
        expect(result.findings).toEqual([]);
    });

    it('genera hallazgos cuando faltan cabeceras de seguridad', async () => {
        httpMock.inspect.mockResolvedValue({
            statusCode: 200,
            headers: {},
        });

        const result = await analyzer.analyze('example.com');

        expect(result.findings.length).toBeGreaterThan(0);

        expect(result.findings).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    title: 'Cabecera de seguridad ausente',
                }),
            ]),
        );
    });

    it('rechaza un dominio vacío sin consultar HTTP', async () => {
        await expect(analyzer.analyze('')).rejects.toThrow();

        expect(httpMock.inspect).not.toHaveBeenCalled();
    });

    it('rechaza un dominio con formato inválido', async () => {
        await expect(
            analyzer.analyze('esto no es un dominio'),
        ).rejects.toThrow();

        expect(httpMock.inspect).not.toHaveBeenCalled();
    });

    it('propaga los errores inesperados de la inspección HTTP', async () => {
        httpMock.inspect.mockRejectedValue(
            new Error('No fue posible consultar las cabeceras HTTP'),
        );

        await expect(
            analyzer.analyze('example.com'),
        ).rejects.toThrow(
            'No fue posible consultar las cabeceras HTTP',
        );
    });
});

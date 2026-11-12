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

    function createInspection(
        headers: Record<string, string | string[]> = {},
    ) {
        return {
            statusCode: 200,
            headers,
            url: 'https://example.com/',
            usesHttps: true,
            server: 'nginx',
        };
    }

    it('consulta las cabeceras HTTP del dominio', async () => {
        httpMock.inspect.mockResolvedValue(createInspection({
            'strict-transport-security': 'max-age=31536000',
            'content-security-policy': "default-src 'self'",
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY',
            'referrer-policy': 'no-referrer',
            'x-xss-protection': '0',
        }));

        await analyzer.analyze('example.com');

        expect(httpMock.inspect).toHaveBeenCalledWith('example.com');
    });

    it('devuelve las cabeceras y la información HTTP recopilada', async () => {
        const headers = {
            'strict-transport-security': 'max-age=31536000',
            'content-security-policy': "default-src 'self'",
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY',
            'referrer-policy': 'no-referrer',
            'x-xss-protection': '0',
        };

        httpMock.inspect.mockResolvedValue(createInspection(headers));

        const result = await analyzer.analyze('example.com');

        expect(result.status).toBe('completed');
        expect(result.statusCode).toBe(200);
        expect(result.headers).toEqual(headers);
        expect(result.url).toBe('https://example.com/');
        expect(result.usesHttps).toBe(true);
        expect(result.server).toBe('nginx');

        expect(result.presentHeaders).toEqual([
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Referrer-Policy',
            'X-XSS-Protection',
        ]);

        expect(result.missingHeaders).toEqual([]);
        expect(result.findings).toEqual([]);
    });

    it('normaliza los nombres de las cabeceras sin importar sus mayúsculas', async () => {
        httpMock.inspect.mockResolvedValue(createInspection({
            'Strict-Transport-Security': 'max-age=31536000',
            'CONTENT-SECURITY-POLICY': "default-src 'self'",
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer',
            'X-XSS-Protection': '0',
        }));

        const result = await analyzer.analyze('example.com');

        expect(result.findings).toEqual([]);
        expect(result.presentHeaders).toHaveLength(6);
    });

    it('genera hallazgos y conserva las cabeceras faltantes', async () => {
        httpMock.inspect.mockResolvedValue(createInspection({}));

        const result = await analyzer.analyze('example.com');

        expect(result.findings).toHaveLength(6);

        expect(result.missingHeaders).toEqual([
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Referrer-Policy',
            'X-XSS-Protection',
        ]);
    });

    it('genera un hallazgo cuando una cabecera está presente como arreglo vacío', async () => {
        httpMock.inspect.mockResolvedValue(createInspection({
            'strict-transport-security': [],
            'content-security-policy': "default-src 'self'",
            'x-content-type-options': 'nosniff',
            'x-frame-options': 'DENY',
            'referrer-policy': 'no-referrer',
            'x-xss-protection': '0',
        }));

        const result = await analyzer.analyze('example.com');

        expect(result.findings).toEqual([
            expect.objectContaining({
                description:
                    'No se encontró Strict-Transport-Security (HSTS).',
            }),
        ]);

        expect(result.missingHeaders).toEqual([
            'Strict-Transport-Security',
        ]);
    });

    it('considera una cabecera vacía como ausente', async () => {
        httpMock.inspect.mockResolvedValue(createInspection({
            'strict-transport-security': '   ',
        }));

        const result = await analyzer.analyze('example.com');

        expect(result.missingHeaders).toContain(
            'Strict-Transport-Security',
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
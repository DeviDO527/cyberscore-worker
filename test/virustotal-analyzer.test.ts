
import {
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';

import {
    VirusTotalAnalyzer,
} from '../src/security/virustotal-analyzer';

interface FetchMock {
    (...args: Parameters<typeof fetch>): Promise<Response>;

    mockResolvedValue(value: Response): FetchMock;

    mockRejectedValue(value: unknown): FetchMock;

    mock: {
        calls: unknown[][];
    };
}

function createFetchMock(): FetchMock {
    return jest.fn() as unknown as FetchMock;
}

function createResponse(
    body: unknown,
    options: {
        ok?: boolean;
        status?: number;
    } = {},
): Response {
    return {
        ok: options.ok ?? true,
        status: options.status ?? 200,
        json: async () => body,
    } as Response;
}

const VALID_API_KEY = 'a'.repeat(64);

describe('VirusTotalAnalyzer', () => {

    it(
        'consulta VirusTotal v3 y extrae estadísticas, categorías y motores de alerta',
        async () => {
            const fetchFn = createFetchMock();

            fetchFn.mockResolvedValue(
                createResponse({
                    data: {
                        attributes: {
                            last_analysis_stats: {
                                malicious: 2,
                                suspicious: 1,
                                harmless: 45,
                                undetected: 8,
                                timeout: 1,
                            },

                            last_analysis_results: {
                                EngineA: {
                                    category: 'malicious',
                                    result: 'phishing',
                                },

                                EngineB: {
                                    category: 'suspicious',
                                    result: 'suspicious',
                                },

                                EngineC: {
                                    category: 'harmless',
                                    result: 'clean',
                                },
                            },

                            reputation: -12,

                            categories: {
                                vendorA: 'technology',
                                vendorB: 'business',
                            },

                            creation_date: 1_577_836_800,
                        },
                    },
                }),
            );

            const analyzer = new VirusTotalAnalyzer({
                apiKey: VALID_API_KEY,
                fetchFn: fetchFn as typeof fetch,
            });

            const result = await analyzer.analyze(
                ' EXAMPLE.COM. ',
            );

            expect(fetchFn).toHaveBeenCalledWith(
                'https://www.virustotal.com/api/v3/domains/example.com',
                expect.objectContaining({
                    method: 'GET',

                    headers: {
                        accept: 'application/json',
                        'x-apikey': VALID_API_KEY,
                    },

                    signal: expect.any(AbortSignal),
                }),
            );

            expect(result).toEqual({
                status: 'completed',
                domain: 'example.com',

                stats: {
                    malicious: 2,
                    suspicious: 1,
                    harmless: 45,
                    undetected: 8,
                    timeout: 1,
                },

                communityReputation: -12,

                categories: [
                    'technology',
                    'business',
                ],

                creationDate: '2020-01-01',

                alertEngines: [
                    {
                        engine: 'EngineA',
                        result: 'phishing',
                        category: 'malicious',
                    },
                    {
                        engine: 'EngineB',
                        result: 'suspicious',
                        category: 'suspicious',
                    },
                ],

                error: null,
            });
        },
    );

    it(
        'no realiza la consulta cuando la API key no está configurada',
        async () => {
            const fetchFn = createFetchMock();

            const analyzer = new VirusTotalAnalyzer({
                fetchFn: fetchFn as typeof fetch,
            });

            const result = await analyzer.analyze(
                'example.com',
            );

            expect(fetchFn).not.toHaveBeenCalled();

            expect(result.status).toBe('unavailable');

            expect(result.stats.malicious).toBe(0);

            expect(result.error).toContain(
                'VIRUSTOTAL_API_KEY',
            );
        },
    );

    it(
        'no realiza la consulta cuando la API key tiene menos de 60 caracteres',
        async () => {
            const fetchFn = createFetchMock();

            const analyzer = new VirusTotalAnalyzer({
                apiKey: 'short-key',
                fetchFn: fetchFn as typeof fetch,
            });

            const result = await analyzer.analyze(
                'example.com',
            );

            expect(fetchFn).not.toHaveBeenCalled();

            expect(result.status).toBe('unavailable');
        },
    );

    it(
        'devuelve categorías predeterminadas cuando VirusTotal no proporciona categorías',
        async () => {
            const fetchFn = createFetchMock();

            fetchFn.mockResolvedValue(
                createResponse({
                    data: {
                        attributes: {},
                    },
                }),
            );

            const analyzer = new VirusTotalAnalyzer({
                apiKey: VALID_API_KEY,
                fetchFn: fetchFn as typeof fetch,
            });

            const result = await analyzer.analyze(
                'example.com',
            );

            expect(result.status).toBe('completed');

            expect(result.categories).toEqual([
                'Sin clasificar',
            ]);

            expect(result.creationDate).toBe(
                'No disponible',
            );

            expect(result.stats).toEqual({
                malicious: 0,
                suspicious: 0,
                harmless: 0,
                undetected: 0,
                timeout: 0,
            });
        },
    );

    it(
        'ignora valores estadísticos que no son números finitos',
        async () => {
            const fetchFn = createFetchMock();

            fetchFn.mockResolvedValue(
                createResponse({
                    data: {
                        attributes: {
                            last_analysis_stats: {
                                malicious: '2',
                                suspicious: -1,
                                harmless: Number.NaN,
                                undetected: 3.8,
                            },
                        },
                    },
                }),
            );

            const analyzer = new VirusTotalAnalyzer({
                apiKey: VALID_API_KEY,
                fetchFn: fetchFn as typeof fetch,
            });

            const result = await analyzer.analyze(
                'example.com',
            );

            expect(result.stats).toEqual({
                malicious: 0,
                suspicious: 0,
                harmless: 0,
                undetected: 3,
                timeout: 0,
            });
        },
    );

    it(
        'devuelve failed cuando la API responde con un estado HTTP distinto de 200',
        async () => {
            const fetchFn = createFetchMock();

            fetchFn.mockResolvedValue(
                createResponse(
                    {},
                    {
                        ok: false,
                        status: 429,
                    },
                ),
            );

            const analyzer = new VirusTotalAnalyzer({
                apiKey: VALID_API_KEY,
                fetchFn: fetchFn as typeof fetch,
            });

            const result = await analyzer.analyze(
                'example.com',
            );

            expect(result.status).toBe('failed');

            expect(result.error).toContain('HTTP 429');

            expect(result.alertEngines).toEqual([]);
        },
    );

    it(
        'devuelve failed cuando la respuesta no contiene data.attributes',
        async () => {
            const fetchFn = createFetchMock();

            fetchFn.mockResolvedValue(
                createResponse({
                    data: {},
                }),
            );

            const analyzer = new VirusTotalAnalyzer({
                apiKey: VALID_API_KEY,
                fetchFn: fetchFn as typeof fetch,
            });

            const result = await analyzer.analyze(
                'example.com',
            );

            expect(result.status).toBe('failed');

            expect(result.error).toContain(
                'data.attributes',
            );
        },
    );

    it(
        'maneja errores de red sin interrumpir el análisis',
        async () => {
            const fetchFn = createFetchMock();

            fetchFn.mockRejectedValue(
                new Error('network unavailable'),
            );

            const analyzer = new VirusTotalAnalyzer({
                apiKey: VALID_API_KEY,
                fetchFn: fetchFn as typeof fetch,
            });

            const result = await analyzer.analyze(
                'example.com',
            );

            expect(result.status).toBe('failed');

            expect(result.error).toContain(
                'network unavailable',
            );
        },
    );

    it(
        'permite configurar una URL base personalizada',
        async () => {
            const fetchFn = createFetchMock();

            fetchFn.mockResolvedValue(
                createResponse({
                    data: {
                        attributes: {},
                    },
                }),
            );

            const analyzer = new VirusTotalAnalyzer({
                apiKey: VALID_API_KEY,

                baseUrl:
                    'https://vt.example.test/api/v3/',

                fetchFn: fetchFn as typeof fetch,
            });

            await analyzer.analyze('example.com');

            expect(fetchFn.mock.calls[0]?.[0]).toBe(
                'https://vt.example.test/api/v3/domains/example.com',
            );
        },
    );

    it('devuelve No disponible cuando la fecha de análisis excede el rango de Date', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValue(createResponse({
            data: {
                attributes: { creation_date: Number.MAX_VALUE },
            },
        }));
        const analyzer = new VirusTotalAnalyzer({
            apiKey: VALID_API_KEY,
            fetchFn: fetchFn as typeof fetch,
        });

        const result = await analyzer.analyze('example.com');

        expect(result.status).toBe('completed');
        expect(result.creationDate).toBe('No disponible');
    });

    it('rechaza dominios vacíos antes de consultar VirusTotal', async () => {
        const fetchFn = createFetchMock();
        const analyzer = new VirusTotalAnalyzer({
            apiKey: VALID_API_KEY,
            fetchFn: fetchFn as typeof fetch,
        });

        await expect(analyzer.analyze('   ')).rejects.toThrow(
            'El dominio es obligatorio para consultar VirusTotal.',
        );
        expect(fetchFn).not.toHaveBeenCalled();
    });

    it('usa las opciones predeterminadas cuando no se proporciona configuración', async () => {
        const analyzer = new VirusTotalAnalyzer();

        const result = await analyzer.analyze('example.com');

        expect(result.status).toBe('unavailable');
        expect(result.error).toContain('VIRUSTOTAL_API_KEY');
    });

    it('conserva errores de transporte que no son instancias de Error', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockRejectedValue('conexión interrumpida');
        const analyzer = new VirusTotalAnalyzer({
            apiKey: VALID_API_KEY,
            fetchFn: fetchFn as typeof fetch,
        });

        const result = await analyzer.analyze('example.com');

        expect(result.status).toBe('failed');
        expect(result.error).toContain('conexión interrumpida');
    });

    it('usa la categoría predeterminada si los valores están vacíos o no son texto', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValue(createResponse({
            data: {
                attributes: {
                    categories: { vendorA: '  ', vendorB: 42 },
                    last_analysis_results: {
                        EngineA: {
                            category: 'malicious',
                            result: null,
                        },
                    },
                },
            },
        }));
        const analyzer = new VirusTotalAnalyzer({
            apiKey: VALID_API_KEY,
            fetchFn: fetchFn as typeof fetch,
        });

        const result = await analyzer.analyze('example.com');

        expect(result.categories).toEqual(['Sin clasificar']);
        expect(result.alertEngines).toEqual([
            {
                engine: 'EngineA',
                result: 'malicious',
                category: 'malicious',
            },
        ]);
    });
});

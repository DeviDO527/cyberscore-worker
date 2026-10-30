import { beforeEach, describe, expect, it, jest } from '@jest/globals';

import { SecurityAnalyzer } from '../src/security/security-analyzer';

describe('SecurityAnalyzer', () => {
    const domain = 'example.com';

    const dnsResult = {
        status: 'completed',
        findings: [],
        records: {
            a: ['203.0.113.10'],
            aaaa: ['2001:db8::10'],
            mx: [
                { exchange: 'mail.example.com', priority: 10 },
            ],
            ns: ['ns1.example.com'],
        },
    };

    const tlsResult = {
        status: 'completed',
        authorized: true,
        protocol: 'TLSv1.3',
        certificate: {
            validFrom: 'Jan 01 00:00:00 2026 GMT',
            validTo: 'Jan 01 00:00:00 2027 GMT',
            subject: { CN: 'example.com' },
            issuer: { CN: 'Example CA' },
        },
        findings: [],
    };

    const headersResult = {
        status: 'completed',
        statusCode: 200,
        headers: {
            'strict-transport-security': 'max-age=31536000',
        },
        findings: [
            {
                title: 'Cabecera de seguridad ausente',
                severity: 'medium',
                description: 'No se encontró una cabecera de seguridad esperada.',
            },
        ],
    };

    let dnsAnalyzer: {
        analyze: ReturnType<typeof jest.fn>;
    };

    let tlsAnalyzer: {
        analyze: ReturnType<typeof jest.fn>;
    };

    let headersAnalyzer: {
        analyze: ReturnType<typeof jest.fn>;
    };

    let analyzer: SecurityAnalyzer;

    beforeEach(() => {
        jest.clearAllMocks();

        dnsAnalyzer = {
            analyze: jest.fn(),
        };

        tlsAnalyzer = {
            analyze: jest.fn(),
        };

        headersAnalyzer = {
            analyze: jest.fn(),
        };

        analyzer = new SecurityAnalyzer({
            dnsAnalyzer,
            tlsAnalyzer,
            headersAnalyzer,
        });
    });

    it('ejecuta los analizadores configurados para el dominio', async () => {
        dnsAnalyzer.analyze.mockResolvedValue(dnsResult);
        tlsAnalyzer.analyze.mockResolvedValue(tlsResult);
        headersAnalyzer.analyze.mockResolvedValue(headersResult);

        await analyzer.analyze(domain);

        expect(dnsAnalyzer.analyze).toHaveBeenCalledWith(domain);
        expect(tlsAnalyzer.analyze).toHaveBeenCalledWith(domain);
        expect(headersAnalyzer.analyze).toHaveBeenCalledWith(domain);
    });

    it('devuelve los hallazgos recopilados de las capas analizadas', async () => {
        dnsAnalyzer.analyze.mockResolvedValue(dnsResult);
        tlsAnalyzer.analyze.mockResolvedValue(tlsResult);
        headersAnalyzer.analyze.mockResolvedValue(headersResult);

        const result = await analyzer.analyze(domain);

        expect(result.findings).toHaveLength(1);

        expect(result.findings).toEqual([
            expect.objectContaining({
                title: 'Cabecera de seguridad ausente',
                severity: 'medium',
            }),
        ]);
    });

    it('resume el estado y el número de hallazgos por capa', async () => {
        dnsAnalyzer.analyze.mockResolvedValue(dnsResult);
        tlsAnalyzer.analyze.mockResolvedValue(tlsResult);
        headersAnalyzer.analyze.mockResolvedValue(headersResult);

        const result = await analyzer.analyze(domain);

        expect(result.layersSummary).toEqual({
            dns: {
                status: 'completed',
                findings: 0,
            },
            tls: {
                status: 'completed',
                findings: 0,
            },
            headers: {
                status: 'completed',
                findings: 1,
            },
        });
    });

    it('rechaza un dominio vacío sin ejecutar los analizadores', async () => {
        await expect(analyzer.analyze('')).rejects.toThrow();

        expect(dnsAnalyzer.analyze).not.toHaveBeenCalled();
        expect(tlsAnalyzer.analyze).not.toHaveBeenCalled();
        expect(headersAnalyzer.analyze).not.toHaveBeenCalled();
    });

    it('rechaza una entrada que no sea un dominio válido', async () => {
        await expect(
            analyzer.analyze('esto no es un dominio'),
        ).rejects.toThrow();

        expect(dnsAnalyzer.analyze).not.toHaveBeenCalled();
        expect(tlsAnalyzer.analyze).not.toHaveBeenCalled();
        expect(headersAnalyzer.analyze).not.toHaveBeenCalled();
    });

    it('propaga el error si una capa falla', async () => {
        const error = new Error('Fallo durante la comprobación TLS');

        dnsAnalyzer.analyze.mockResolvedValue(dnsResult);
        tlsAnalyzer.analyze.mockRejectedValue(error);
        headersAnalyzer.analyze.mockResolvedValue(headersResult);

        await expect(analyzer.analyze(domain)).rejects.toThrow(
            'Fallo durante la comprobación TLS',
        );
    });

    it('devuelve un resultado vacío cuando las capas terminan sin hallazgos', async () => {
        dnsAnalyzer.analyze.mockResolvedValue({
            status: 'completed',
            findings: [],
            records: {
                a: [],
                aaaa: [],
                mx: [],
                ns: [],
            },
        });
    
        tlsAnalyzer.analyze.mockResolvedValue({
            status: 'completed',
            findings: [],
        });
    
        headersAnalyzer.analyze.mockResolvedValue({
            status: 'completed',
            statusCode: 200,
            headers: {},
            findings: [],
        });
    
        const result = await analyzer.analyze('example.com');
    
        expect(result.findings).toEqual([]);
    
        expect(result.layersSummary).toEqual({
            dns: {
                status: 'completed',
                findings: 0,
            },
            tls: {
                status: 'completed',
                findings: 0,
            },
            headers: {
                status: 'completed',
                findings: 0,
            },
        });
    });

    it('conserva los registros DNS en el resultado consolidado', async () => {
        dnsAnalyzer.analyze.mockResolvedValue(dnsResult);
        tlsAnalyzer.analyze.mockResolvedValue(tlsResult);
        headersAnalyzer.analyze.mockResolvedValue(headersResult);

        const result = await analyzer.analyze(domain);

        expect(result.dnsRecords).toEqual(dnsResult.records);
    });

    it('asigna la capa y conserva evidencia de los hallazgos HTTP', async () => {
        dnsAnalyzer.analyze.mockResolvedValue(dnsResult);
        tlsAnalyzer.analyze.mockResolvedValue(tlsResult);
        headersAnalyzer.analyze.mockResolvedValue(headersResult);

        const result = await analyzer.analyze(domain);

        expect(result.findings).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    layer: 'headers',
                    title: 'Cabecera de seguridad ausente',
                    severity: 'medium',
                    evidence: JSON.stringify({
                        statusCode: 200,
                        headers: headersResult.headers,
                    }),
                }),
            ]),
        );
    });

    it('asigna la capa y conserva evidencia de los hallazgos TLS', async () => {
        const tlsFailure = {
            ...tlsResult,
            authorized: false,
            protocol: 'TLSv1.2',
            findings: [
                {
                    title: 'Certificado TLS no autorizado',
                    severity: 'high',
                    description: 'No se pudo validar el certificado.',
                },
            ],
        };

        dnsAnalyzer.analyze.mockResolvedValue(dnsResult);
        tlsAnalyzer.analyze.mockResolvedValue(tlsFailure);
        headersAnalyzer.analyze.mockResolvedValue({
            ...headersResult,
            findings: [],
        });

        const result = await analyzer.analyze(domain);

        expect(result.findings).toEqual(
            expect.arrayContaining([
                expect.objectContaining({
                    layer: 'tls',
                    title: 'Certificado TLS no autorizado',
                    severity: 'high',
                    evidence: JSON.stringify({
                        authorized: false,
                        protocol: 'TLSv1.2',
                        certificate: tlsResult.certificate,
                    }),
                }),
            ]),
        );
    });

});

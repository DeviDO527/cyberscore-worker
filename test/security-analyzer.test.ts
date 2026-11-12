import {
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';

import {
    DnsAnalysisResult,
} from '../src/security/dns-analyzer';

import {
    HeadersAnalysisResult,
} from '../src/security/headers-analyzer';

import {
    SecurityAnalyzer,
} from '../src/security/security-analyzer';

import {
    TlsAnalysisResult,
} from '../src/security/tls-analyzer';

describe('SecurityAnalyzer', () => {
    type AnalyzerMock<T> = {
        analyze: jest.Mock<
            (domain: string) => Promise<T>
        >;
    };

    function createDnsRecords() {
        return {
            a: [],
            aaaa: [],
            mx: [],
            ns: [],
        };
    }

    function createAnalyzer() {
        const dnsAnalyzer: AnalyzerMock<DnsAnalysisResult> = {
            analyze: jest.fn<
                (domain: string) =>
                    Promise<DnsAnalysisResult>
            >(),
        };

        const tlsAnalyzer: AnalyzerMock<TlsAnalysisResult> = {
            analyze: jest.fn<
                (domain: string) =>
                    Promise<TlsAnalysisResult>
            >(),
        };

        const headersAnalyzer:
            AnalyzerMock<HeadersAnalysisResult> = {
                analyze: jest.fn<
                    (domain: string) =>
                        Promise<HeadersAnalysisResult>
                >(),
            };

        const analyzer = new SecurityAnalyzer({
            dnsAnalyzer,
            tlsAnalyzer,
            headersAnalyzer,
        });

        return {
            analyzer,
            dnsAnalyzer,
            tlsAnalyzer,
            headersAnalyzer,
        };
    }

    function configureSuccessfulAnalysis(
        dnsAnalyzer: AnalyzerMock<DnsAnalysisResult>,
        tlsAnalyzer: AnalyzerMock<TlsAnalysisResult>,
        headersAnalyzer:
            AnalyzerMock<HeadersAnalysisResult>,
    ): void {
        dnsAnalyzer.analyze.mockResolvedValue({
            status: 'completed',
            findings: [],
            records: createDnsRecords(),
        });

        tlsAnalyzer.analyze.mockResolvedValue({
            status: 'completed',
            authorized: true,
            protocol: 'TLSv1.3',
            certificate: {
                validFrom:
                    'Jan 01 00:00:00 2026 GMT',
                validTo:
                    'Jan 01 00:00:00 2027 GMT',
                daysRemaining: 55,
                subject: {
                    CN: 'example.com',
                },
                issuer: {
                    CN: 'Example CA',
                },
            },
            findings: [],
        });

        headersAnalyzer.analyze.mockResolvedValue({
            status: 'completed',
            statusCode: 200,
            headers: {
                'content-security-policy':
                    "default-src 'self'",
            },
            url: 'https://example.com/',
            usesHttps: true,
            server: 'nginx',
            presentHeaders: [
                'Content-Security-Policy',
            ],
            missingHeaders: [
                'X-Frame-Options',
            ],
            findings: [],
        });
    }

    it(
        'ejecuta todos los analizadores para el dominio',
        async () => {
            const {
                analyzer,
                dnsAnalyzer,
                tlsAnalyzer,
                headersAnalyzer,
            } = createAnalyzer();

            configureSuccessfulAnalysis(
                dnsAnalyzer,
                tlsAnalyzer,
                headersAnalyzer,
            );

            await analyzer.analyze('example.com');

            expect(
                dnsAnalyzer.analyze,
            ).toHaveBeenCalledWith('example.com');

            expect(
                tlsAnalyzer.analyze,
            ).toHaveBeenCalledWith('example.com');

            expect(
                headersAnalyzer.analyze,
            ).toHaveBeenCalledWith('example.com');
        },
    );

    it(
        'consolida la información completa de las capas',
        async () => {
            const {
                analyzer,
                dnsAnalyzer,
                tlsAnalyzer,
                headersAnalyzer,
            } = createAnalyzer();

            configureSuccessfulAnalysis(
                dnsAnalyzer,
                tlsAnalyzer,
                headersAnalyzer,
            );

            const result =
                await analyzer.analyze('example.com');

            expect(result.layersSummary).toEqual({
                dns: {
                    status: 'completed',
                    findings: 0,
                },
                tls: {
                    status: 'completed',
                    findings: 0,
                    authorized: true,
                    protocol: 'TLSv1.3',
                    certificate: {
                        validFrom:
                            'Jan 01 00:00:00 2026 GMT',
                        validTo:
                            'Jan 01 00:00:00 2027 GMT',
                        daysRemaining: 55,
                        subject: {
                            CN: 'example.com',
                        },
                        issuer: {
                            CN: 'Example CA',
                        },
                    },
                },
                headers: {
                    status: 'completed',
                    findings: 0,
                    statusCode: 200,
                    url: 'https://example.com/',
                    usesHttps: true,
                    server: 'nginx',
                    presentHeaders: [
                        'Content-Security-Policy',
                    ],
                    missingHeaders: [
                        'X-Frame-Options',
                    ],
                },
            });
        },
    );

    it(
        'conserva los registros DNS en el resultado',
        async () => {
            const {
                analyzer,
                dnsAnalyzer,
                tlsAnalyzer,
                headersAnalyzer,
            } = createAnalyzer();

            configureSuccessfulAnalysis(
                dnsAnalyzer,
                tlsAnalyzer,
                headersAnalyzer,
            );

            const result =
                await analyzer.analyze('example.com');

            expect(result.dnsRecords).toEqual(
                createDnsRecords(),
            );
        },
    );

    it(
        'consolida los hallazgos y su evidencia',
        async () => {
            const {
                analyzer,
                dnsAnalyzer,
                tlsAnalyzer,
                headersAnalyzer,
            } = createAnalyzer();

            dnsAnalyzer.analyze.mockResolvedValue({
                status: 'completed',
                findings: [
                    {
                        title: 'Problema DNS',
                        severity: 'medium',
                        description:
                            'El dominio presenta un problema DNS.',
                    },
                ],
                records: createDnsRecords(),
            });

            tlsAnalyzer.analyze.mockResolvedValue({
                status: 'completed',
                authorized: false,
                protocol: 'TLSv1.2',
                certificate: {
                    validFrom:
                        'Jan 01 00:00:00 2026 GMT',
                    validTo:
                        'Jan 01 00:00:00 2027 GMT',
                    daysRemaining: 55,
                    subject: {
                        CN: 'example.com',
                    },
                    issuer: {
                        CN: 'Unknown CA',
                    },
                },
                findings: [
                    {
                        title:
                            'Certificado TLS no autorizado',
                        severity: 'high',
                        description:
                            'No fue posible validar el certificado.',
                    },
                ],
            });

            headersAnalyzer.analyze.mockResolvedValue({
                status: 'completed',
                statusCode: 200,
                headers: {},
                url: 'https://example.com/',
                usesHttps: true,
                server: null,
                presentHeaders: [],
                missingHeaders: [
                    'Content-Security-Policy',
                ],
                findings: [
                    {
                        title:
                            'Cabecera de seguridad ausente',
                        severity: 'medium',
                        description:
                            'No se encontró Content-Security-Policy.',
                    },
                ],
            });

            const result =
                await analyzer.analyze('example.com');

            expect(result.findings).toHaveLength(3);

            expect(result.findings).toEqual(
                expect.arrayContaining([
                    expect.objectContaining({
                        layer: 'dns',
                        title: 'Problema DNS',
                    }),
                    expect.objectContaining({
                        layer: 'tls',
                        title:
                            'Certificado TLS no autorizado',
                    }),
                    expect.objectContaining({
                        layer: 'headers',
                        title:
                            'Cabecera de seguridad ausente',
                    }),
                ]),
            );

            const tlsFinding = result.findings.find(
                finding => finding.layer === 'tls',
            );

            expect(tlsFinding?.evidence).toContain(
                '"daysRemaining":55',
            );
        },
    );

    it(
        'conserva la información TLS aunque no existan hallazgos',
        async () => {
            const {
                analyzer,
                dnsAnalyzer,
                tlsAnalyzer,
                headersAnalyzer,
            } = createAnalyzer();

            configureSuccessfulAnalysis(
                dnsAnalyzer,
                tlsAnalyzer,
                headersAnalyzer,
            );

            const result =
                await analyzer.analyze('example.com');

            expect(
                result.layersSummary.tls.certificate.issuer,
            ).toEqual({
                CN: 'Example CA',
            });

            expect(
                result.layersSummary.tls.certificate
                    .daysRemaining,
            ).toBe(55);
        },
    );

    it(
        'conserva la información HTTP aunque no existan hallazgos',
        async () => {
            const {
                analyzer,
                dnsAnalyzer,
                tlsAnalyzer,
                headersAnalyzer,
            } = createAnalyzer();

            configureSuccessfulAnalysis(
                dnsAnalyzer,
                tlsAnalyzer,
                headersAnalyzer,
            );

            const result =
                await analyzer.analyze('example.com');

            expect(
                result.layersSummary.headers.statusCode,
            ).toBe(200);

            expect(
                result.layersSummary.headers.server,
            ).toBe('nginx');

            expect(
                result.layersSummary.headers.presentHeaders,
            ).toEqual([
                'Content-Security-Policy',
            ]);
        },
    );

    it(
        'propaga un error cuando uno de los analizadores falla',
        async () => {
            const {
                analyzer,
                dnsAnalyzer,
                tlsAnalyzer,
                headersAnalyzer,
            } = createAnalyzer();

            configureSuccessfulAnalysis(
                dnsAnalyzer,
                tlsAnalyzer,
                headersAnalyzer,
            );

            tlsAnalyzer.analyze.mockRejectedValue(
                new Error(
                    'No fue posible analizar TLS',
                ),
            );

            await expect(
                analyzer.analyze('example.com'),
            ).rejects.toThrow(
                'No fue posible analizar TLS',
            );
        },
    );

    it('rechaza dominios vacíos antes de iniciar análisis', async () => {
        const { analyzer, dnsAnalyzer, tlsAnalyzer, headersAnalyzer } = createAnalyzer();

        await expect(analyzer.analyze('   ')).rejects.toThrow('El dominio es obligatorio');
        expect(dnsAnalyzer.analyze).not.toHaveBeenCalled();
        expect(tlsAnalyzer.analyze).not.toHaveBeenCalled();
        expect(headersAnalyzer.analyze).not.toHaveBeenCalled();
    });

    it('rechaza dominios con formato inválido antes de iniciar análisis', async () => {
        const { analyzer, dnsAnalyzer, tlsAnalyzer, headersAnalyzer } = createAnalyzer();

        await expect(analyzer.analyze('https://example.com')).rejects.toThrow(
            'El dominio no tiene un formato válido',
        );
        expect(dnsAnalyzer.analyze).not.toHaveBeenCalled();
        expect(tlsAnalyzer.analyze).not.toHaveBeenCalled();
        expect(headersAnalyzer.analyze).not.toHaveBeenCalled();
    });
});
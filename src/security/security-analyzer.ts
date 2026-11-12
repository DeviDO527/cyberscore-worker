import type { DnsRecords } from './dns-analyzer';

export interface SecurityFinding {
    title: string;
    severity: string;
    description: string;
}

export interface EnrichedSecurityFinding extends SecurityFinding {
    layer: 'dns' | 'tls' | 'headers';
    evidence: string | null;
}

export interface LayerAnalysisResult {
    status: string;
    findings: SecurityFinding[];
}

export interface DnsLayerAnalysisResult
    extends LayerAnalysisResult {
    records: DnsRecords;
}

export interface TlsLayerAnalysisResult
    extends LayerAnalysisResult {
    authorized: boolean;
    protocol: string;
    certificate: {
        validFrom: string;
        validTo: string;
        daysRemaining: number | null;
        subject: Record<string, unknown>;
        issuer: Record<string, unknown>;
    };
}

export interface HeadersLayerAnalysisResult
    extends LayerAnalysisResult {
    statusCode: number;
    headers: Record<
        string,
        string | string[] | undefined
    >;
    url: string;
    usesHttps: boolean;
    server: string | null;
    presentHeaders: string[];
    missingHeaders: string[];
}

export interface SecurityLayerAnalyzer<
    TResult extends LayerAnalysisResult = LayerAnalysisResult,
> {
    analyze(domain: string): Promise<TResult>;
}

export interface SecurityAnalyzerDependencies {
    dnsAnalyzer: SecurityLayerAnalyzer<DnsLayerAnalysisResult>;
    tlsAnalyzer: SecurityLayerAnalyzer<TlsLayerAnalysisResult>;
    headersAnalyzer: SecurityLayerAnalyzer<HeadersLayerAnalysisResult>;
}

export interface SecurityLayersSummary {
    dns: {
        status: string;
        findings: number;
    };
    tls: {
        status: string;
        findings: number;
        authorized: boolean;
        protocol: string;
        certificate: {
            validFrom: string;
            validTo: string;
            daysRemaining: number | null;
            subject: Record<string, unknown>;
            issuer: Record<string, unknown>;
        };
    };
    headers: {
        status: string;
        findings: number;
        statusCode: number;
        url: string;
        usesHttps: boolean;
        server: string | null;
        presentHeaders: string[];
        missingHeaders: string[];
    };
}

export interface SecurityAnalysisResult {
    findings: EnrichedSecurityFinding[];
    dnsRecords: DnsRecords;
    layersSummary: SecurityLayersSummary;
}

export class SecurityAnalyzer {
    constructor(
        private readonly dependencies: SecurityAnalyzerDependencies,
    ) {}

    async analyze(
        domain: string,
    ): Promise<SecurityAnalysisResult> {
        if (
            typeof domain !== 'string' ||
            domain.trim().length === 0
        ) {
            throw new Error('El dominio es obligatorio');
        }

        const normalizedDomain = domain.trim();

        const validDomain =
            normalizedDomain.length <= 253 &&
            normalizedDomain.includes('.') &&
            /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/.test(
                normalizedDomain,
            );

        if (!validDomain) {
            throw new Error(
                'El dominio no tiene un formato válido',
            );
        }

        const [
            dnsResult,
            tlsResult,
            headersResult,
        ] = await Promise.all([
            this.dependencies.dnsAnalyzer.analyze(
                normalizedDomain,
            ),
            this.dependencies.tlsAnalyzer.analyze(
                normalizedDomain,
            ),
            this.dependencies.headersAnalyzer.analyze(
                normalizedDomain,
            ),
        ]);

        const dnsEvidence = JSON.stringify({
            records: dnsResult.records,
        });

        const tlsEvidence = JSON.stringify({
            authorized: tlsResult.authorized,
            protocol: tlsResult.protocol,
            certificate: tlsResult.certificate,
        });

        const relevantHeaders = new Set([
            'strict-transport-security',
            'content-security-policy',
            'x-content-type-options',
            'x-frame-options',
            'referrer-policy',
            'permissions-policy',
            'cross-origin-embedder-policy',
            'cross-origin-opener-policy',
            'cross-origin-resource-policy',
            'x-xss-protection',
        ]);

        const safeHeaders = Object.fromEntries(
            Object.entries(headersResult.headers).filter(
                ([name]) =>
                    relevantHeaders.has(
                        name.toLowerCase(),
                    ),
            ),
        );

        const headersEvidence = JSON.stringify({
            statusCode: headersResult.statusCode,
            url: headersResult.url,
            usesHttps: headersResult.usesHttps,
            server: headersResult.server,
            headers: safeHeaders,
        });

        const dnsFindings: EnrichedSecurityFinding[] =
            dnsResult.findings.map(finding => ({
                ...finding,
                layer: 'dns',
                evidence: dnsEvidence,
            }));

        const tlsFindings: EnrichedSecurityFinding[] =
            tlsResult.findings.map(finding => ({
                ...finding,
                layer: 'tls',
                evidence: tlsEvidence,
            }));

        const headersFindings: EnrichedSecurityFinding[] =
            headersResult.findings.map(finding => ({
                ...finding,
                layer: 'headers',
                evidence: headersEvidence,
            }));

        const findings: EnrichedSecurityFinding[] = [
            ...dnsFindings,
            ...tlsFindings,
            ...headersFindings,
        ];

        return {
            findings,

            dnsRecords: dnsResult.records,

            layersSummary: {
                dns: {
                    status: dnsResult.status,
                    findings: dnsFindings.length,
                },

                tls: {
                    status: tlsResult.status,
                    findings: tlsFindings.length,
                    authorized: tlsResult.authorized,
                    protocol: tlsResult.protocol,
                    certificate: tlsResult.certificate,
                },

                headers: {
                    status: headersResult.status,
                    findings: headersFindings.length,
                    statusCode:
                        headersResult.statusCode,
                    url: headersResult.url,
                    usesHttps:
                        headersResult.usesHttps,
                    server: headersResult.server,
                    presentHeaders:
                        headersResult.presentHeaders,
                    missingHeaders:
                        headersResult.missingHeaders,
                },
            },
        };
    }
}
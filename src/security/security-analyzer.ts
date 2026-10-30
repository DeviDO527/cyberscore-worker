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

export interface DnsLayerAnalysisResult extends LayerAnalysisResult {
    records: DnsRecords;
}

export interface TlsLayerAnalysisResult extends LayerAnalysisResult {
    authorized: boolean;
    protocol: string;
    certificate: {
        validFrom: string;
        validTo: string;
        subject: Record<string, unknown>;
        issuer: Record<string, unknown>;
    };
}

export interface HeadersLayerAnalysisResult extends LayerAnalysisResult {
    statusCode: number;
    headers: Record<string, string | string[] | undefined>;
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
    };
    headers: {
        status: string;
        findings: number;
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

    async analyze(domain: string): Promise<SecurityAnalysisResult> {
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
            throw new Error('El dominio no tiene un formato válido');
        }

        // Ejecutar los tres analizadores.
        const [dnsResult, tlsResult, headersResult] =
            await Promise.all([
                this.dependencies.dnsAnalyzer.analyze(normalizedDomain),
                this.dependencies.tlsAnalyzer.analyze(normalizedDomain),
                this.dependencies.headersAnalyzer.analyze(normalizedDomain),
            ]);

        // Evidencia DNS.
        const dnsEvidence = JSON.stringify({
            records: dnsResult.records,
        });

        // Evidencia TLS.
        const tlsEvidence = JSON.stringify({
            authorized: tlsResult.authorized,
            protocol: tlsResult.protocol,
            certificate: tlsResult.certificate,
        });

        // Evitar almacenar cabeceras que puedan contener
        // cookies u otros datos sensibles.
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
        ]);

        const safeHeaders = Object.fromEntries(
            Object.entries(headersResult.headers).filter(
                ([name]) => relevantHeaders.has(name.toLowerCase()),
            ),
        );

        const headersEvidence = JSON.stringify({
            statusCode: headersResult.statusCode,
            headers: safeHeaders,
        });

        // Enriquecer los hallazgos con su procedencia y evidencia.
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
                },
                headers: {
                    status: headersResult.status,
                    findings: headersFindings.length,
                },
            },
        };
    }
}
import type { DnsRecords } from './dns-analyzer';

export interface SecurityFinding {
    title: string;
    severity: string;
    description: string;
}

export interface LayerAnalysisResult {
    status: string;
    findings: SecurityFinding[];
}

export interface DnsLayerAnalysisResult extends LayerAnalysisResult {
    records: DnsRecords;
}

export interface SecurityLayerAnalyzer {
    analyze(domain: string): Promise<LayerAnalysisResult>;
}

export interface DnsSecurityLayerAnalyzer {
    analyze(domain: string): Promise<DnsLayerAnalysisResult>;
}

export interface SecurityAnalyzerDependencies {
    dnsAnalyzer: DnsSecurityLayerAnalyzer;
    tlsAnalyzer: SecurityLayerAnalyzer;
    headersAnalyzer: SecurityLayerAnalyzer;
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
    findings: SecurityFinding[];
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

        if (
            normalizedDomain.length > 253 ||
            !/^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/.test(
                normalizedDomain,
            ) ||
            !normalizedDomain.includes('.')
        ) {
            throw new Error('El dominio no tiene un formato válido');
        }

        // Ejecutar los tres analizadores.
        const [dnsResult, tlsResult, headersResult] =
            await Promise.all([
                this.dependencies.dnsAnalyzer.analyze(normalizedDomain),
                this.dependencies.tlsAnalyzer.analyze(normalizedDomain),
                this.dependencies.headersAnalyzer.analyze(normalizedDomain),
            ]);

        // Consolidar exclusivamente los hallazgos reales.
        const findings: SecurityFinding[] = [
            ...dnsResult.findings,
            ...tlsResult.findings,
            ...headersResult.findings,
        ];

        return {
            findings,

            // Conservar los registros DNS para el resultado final.
            dnsRecords: dnsResult.records,

            layersSummary: {
                dns: {
                    status: dnsResult.status,
                    findings: dnsResult.findings.length,
                },

                tls: {
                    status: tlsResult.status,
                    findings: tlsResult.findings.length,
                },

                headers: {
                    status: headersResult.status,
                    findings: headersResult.findings.length,
                },
            },
        };
    }
}
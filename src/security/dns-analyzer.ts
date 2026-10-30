import type { MxRecord } from 'node:dns';

export interface DnsResolver {
    resolve4(domain: string): Promise<string[]>;
    resolve6(domain: string): Promise<string[]>;
    resolveMx(domain: string): Promise<MxRecord[]>;
    resolveNs(domain: string): Promise<string[]>;
}

export interface DnsRecords {
    a: string[];
    aaaa: string[];
    mx: MxRecord[];
    ns: string[];
}

export interface DnsAnalysisResult {
    status: 'completed';
    findings: {
        title: string;
        severity: string;
        description: string;
    }[];
    records: DnsRecords;
}

export class DnsAnalyzer {
    constructor(
        private readonly resolver: DnsResolver,
    ) {}

    async analyze(domain: string): Promise<DnsAnalysisResult> {
        if (
            typeof domain !== 'string' ||
            domain.trim().length === 0
        ) {
            throw new Error('El dominio es obligatorio.');
        }

        const normalizedDomain = domain.trim();

        const validDomain =
            normalizedDomain.length <= 253 &&
            normalizedDomain.includes('.') &&
            /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/.test(
                normalizedDomain,
            );

        if (!validDomain) {
            throw new Error('El dominio no tiene un formato válido.');
        }

        const [a, aaaa, mx, ns] = await Promise.all([
            this.resolver.resolve4(normalizedDomain),
            this.resolver.resolve6(normalizedDomain),
            this.resolver.resolveMx(normalizedDomain),
            this.resolver.resolveNs(normalizedDomain),
        ]);

        return {
            status: 'completed',

            // La consulta DNS no genera por sí misma vulnerabilidades.
            findings: [],

            records: {
                a,
                aaaa,
                mx,
                ns,
            },
        };
    }
}
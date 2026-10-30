import { Resolver } from 'node:dns/promises';
import type { MxRecord } from 'node:dns';

export interface DnsResolver {
    resolve4(domain: string): Promise<string[]>;
    resolve6(domain: string): Promise<string[]>;
    resolveMx(domain: string): Promise<MxRecord[]>;
    resolveNs(domain: string): Promise<string[]>;
}

export interface DnsInspectionResult {
    a: string[];
    aaaa: string[];
    mx: MxRecord[];
    ns: string[];
}

export class DnsInspector {
    constructor(
        private readonly resolver: DnsResolver = new Resolver(),
    ) {}

    async inspect(domain: string): Promise<DnsInspectionResult> {
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
            a,
            aaaa,
            mx,
            ns,
        };
    }
}

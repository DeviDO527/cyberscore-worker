export interface TlsCertificate {
    validFrom: string;
    validTo: string;
    subject: Record<string, unknown>;
    issuer: Record<string, unknown>;
}

export interface TlsInspection {
    authorized: boolean;
    authorizationError?: string;
    protocol: string;
    validFrom: string;
    validTo: string;
    subject: Record<string, unknown>;
    issuer: Record<string, unknown>;
}

export interface TlsInspector {
    inspect(domain: string): Promise<TlsInspection>;
}

export interface TlsFinding {
    title: string;
    severity: string;
    description: string;
}

export interface TlsAnalysisResult {
    status: 'completed';
    authorized: boolean;
    protocol: string;
    certificate: TlsCertificate;
    findings: TlsFinding[];
}

export class TlsAnalyzer {
    constructor(
        private readonly inspector: TlsInspector,
    ) {}

    async analyze(domain: string): Promise<TlsAnalysisResult> {
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

        const inspection = await this.inspector.inspect(normalizedDomain);

        const findings: TlsFinding[] = [];

        if (!inspection.authorized) {
            findings.push({
                title: 'Certificado TLS no autorizado',
                severity: 'high',
                description:
                    `No se pudo validar la confianza del certificado TLS. ${
                        inspection.authorizationError
                            ? `Detalle: ${inspection.authorizationError}`
                            : 'La causa no fue especificada.'
                    }`,
            });
        }

        return {
            status: 'completed',
            authorized: inspection.authorized,
            protocol: inspection.protocol,
            certificate: {
                validFrom: inspection.validFrom,
                validTo: inspection.validTo,
                subject: inspection.subject,
                issuer: inspection.issuer,
            },
            findings,
        };
    }
}

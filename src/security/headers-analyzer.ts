type HeaderValue = string | string[] | undefined;

export interface HttpInspection {
    statusCode: number;
    headers: Record<string, HeaderValue>;
}

export interface HttpInspector {
    inspect(domain: string): Promise<HttpInspection>;
}

export interface HeaderFinding {
    title: string;
    severity: string;
    description: string;
}

export interface HeadersAnalysisResult {
    status: 'completed';
    statusCode: number;
    headers: Record<string, HeaderValue>;
    findings: HeaderFinding[];
}

export class HeadersAnalyzer {
    constructor(
        private readonly inspector: HttpInspector,
    ) {}

    async analyze(domain: string): Promise<HeadersAnalysisResult> {
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

        const normalizedHeaders: Record<
            string,
            string | string[] | undefined
        > = {};

        for (const [name, value] of Object.entries(inspection.headers)) {
            normalizedHeaders[name.toLowerCase()] = value;
        }

        const findings: HeaderFinding[] = [];

        const requiredHeaders = [
            {
                name: 'strict-transport-security',
                title: 'Cabecera de seguridad ausente',
                description:
                    'No se encontró Strict-Transport-Security (HSTS).',
                severity: 'medium',
            },
            {
                name: 'content-security-policy',
                title: 'Cabecera de seguridad ausente',
                description:
                    'No se encontró Content-Security-Policy (CSP).',
                severity: 'medium',
            },
            {
                name: 'x-content-type-options',
                title: 'Cabecera de seguridad ausente',
                description:
                    'No se encontró X-Content-Type-Options.',
                severity: 'low',
            },
            {
                name: 'x-frame-options',
                title: 'Cabecera de seguridad ausente',
                description:
                    'No se encontró X-Frame-Options.',
                severity: 'low',
            },
            {
                name: 'referrer-policy',
                title: 'Cabecera de seguridad ausente',
                description:
                    'No se encontró Referrer-Policy.',
                severity: 'low',
            },
        ];

        for (const header of requiredHeaders) {
            const value = normalizedHeaders[header.name];

            if (
                value === undefined ||
                (typeof value === 'string' && value.trim().length === 0) ||
                (Array.isArray(value) && value.length === 0)
            ) {
                findings.push({
                    title: header.title,
                    severity: header.severity,
                    description: header.description,
                });
            }
        }

        return {
            status: 'completed',
            statusCode: inspection.statusCode,
            headers: normalizedHeaders,
            findings,
        };
    }
}

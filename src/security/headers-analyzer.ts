type HeaderValue = string | string[] | undefined;

export interface HttpInspection {
    statusCode: number;
    headers: Record<string, HeaderValue>;
    url: string;
    usesHttps: boolean;
    server: string | null;
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
    url: string;
    usesHttps: boolean;
    server: string | null;
    presentHeaders: string[];
    missingHeaders: string[];
    findings: HeaderFinding[];
}

interface RequiredSecurityHeader {
    name: string;
    displayName: string;
    title: string;
    description: string;
    severity: string;
}

const REQUIRED_HEADERS: RequiredSecurityHeader[] = [
    {
        name: 'strict-transport-security',
        displayName: 'Strict-Transport-Security',
        title: 'Cabecera de seguridad ausente',
        description: 'No se encontró Strict-Transport-Security (HSTS).',
        severity: 'medium',
    },
    {
        name: 'content-security-policy',
        displayName: 'Content-Security-Policy',
        title: 'Cabecera de seguridad ausente',
        description: 'No se encontró Content-Security-Policy (CSP).',
        severity: 'medium',
    },
    {
        name: 'x-content-type-options',
        displayName: 'X-Content-Type-Options',
        title: 'Cabecera de seguridad ausente',
        description: 'No se encontró X-Content-Type-Options.',
        severity: 'low',
    },
    {
        name: 'x-frame-options',
        displayName: 'X-Frame-Options',
        title: 'Cabecera de seguridad ausente',
        description: 'No se encontró X-Frame-Options.',
        severity: 'low',
    },
    {
        name: 'referrer-policy',
        displayName: 'Referrer-Policy',
        title: 'Cabecera de seguridad ausente',
        description: 'No se encontró Referrer-Policy.',
        severity: 'low',
    },
    {
        name: 'x-xss-protection',
        displayName: 'X-XSS-Protection',
        title: 'Cabecera de seguridad ausente',
        description: 'No se encontró X-XSS-Protection.',
        severity: 'low',
    },
];

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

        const normalizedHeaders: Record<string, HeaderValue> = {};

        for (const [name, value] of Object.entries(inspection.headers)) {
            normalizedHeaders[name.toLowerCase()] = value;
        }

        const findings: HeaderFinding[] = [];
        const presentHeaders: string[] = [];
        const missingHeaders: string[] = [];

        for (const header of REQUIRED_HEADERS) {
            const value = normalizedHeaders[header.name];

            const isMissing =
                value === undefined ||
                (typeof value === 'string' && value.trim().length === 0) ||
                (Array.isArray(value) && value.length === 0);

            if (isMissing) {
                missingHeaders.push(header.displayName);

                findings.push({
                    title: header.title,
                    severity: header.severity,
                    description: header.description,
                });

                continue;
            }

            presentHeaders.push(header.displayName);
        }

        return {
            status: 'completed',
            statusCode: inspection.statusCode,
            headers: normalizedHeaders,
            url: inspection.url,
            usesHttps: inspection.usesHttps,
            server: inspection.server,
            presentHeaders,
            missingHeaders,
            findings,
        };
    }
}
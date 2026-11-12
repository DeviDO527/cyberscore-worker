
export interface VirusTotalStats {
    malicious: number;
    suspicious: number;
    harmless: number;
    undetected: number;
    timeout: number;
}

export interface VirusTotalAlertEngine {
    engine: string;
    result: string;
    category: 'malicious' | 'suspicious';
}

export interface VirusTotalAnalysisResult {
    status: 'completed' | 'unavailable' | 'failed';
    domain: string;
    stats: VirusTotalStats;
    communityReputation: number;
    categories: string[];
    creationDate: string;
    alertEngines: VirusTotalAlertEngine[];
    error: string | null;
}

export interface VirusTotalAnalyzerOptions {
    apiKey?: string;
    baseUrl?: string;
    fetchFn?: typeof fetch;
    timeoutMs?: number;
}

interface VirusTotalVendorResult {
    category?: unknown;
    result?: unknown;
}

interface VirusTotalAttributes {
    last_analysis_stats?: Record<string, unknown>;
    last_analysis_results?: Record<string, VirusTotalVendorResult>;
    reputation?: unknown;
    categories?: Record<string, unknown>;
    creation_date?: unknown;
}

interface VirusTotalResponse {
    data?: {
        attributes?: VirusTotalAttributes;
    };
}

const DEFAULT_STATS: VirusTotalStats = {
    malicious: 0,
    suspicious: 0,
    harmless: 0,
    undetected: 0,
    timeout: 0,
};

export class VirusTotalAnalyzer {
    private readonly apiKey: string | undefined;

    private readonly baseUrl: string;

    private readonly fetchFn: typeof fetch;

    private readonly timeoutMs: number;

    constructor(options: VirusTotalAnalyzerOptions = {}) {
        this.apiKey = options.apiKey?.trim();

        this.baseUrl = (
            options.baseUrl ??
            'https://www.virustotal.com/api/v3'
        ).replace(/\/$/, '');

        this.fetchFn = options.fetchFn ?? fetch;

        this.timeoutMs = options.timeoutMs ?? 10_000;
    }

    async analyze(
        domain: string,
    ): Promise<VirusTotalAnalysisResult> {
        const normalizedDomain = this.normalizeDomain(domain);

        // Equivalente a la validación del worker Python:
        // si no existe API key o tiene menos de 60 caracteres,
        // no se realiza la consulta.

        if (!this.apiKey || this.apiKey.length < 60) {
            return this.createResult(
                'unavailable',
                normalizedDomain,
                'VIRUSTOTAL_API_KEY no está configurada o no tiene un formato válido.',
            );
        }

        try {
            const response = await this.fetchFn(
                `${this.baseUrl}/domains/${encodeURIComponent(normalizedDomain)}`,
                {
                    method: 'GET',
                    headers: {
                        accept: 'application/json',
                        'x-apikey': this.apiKey,
                    },
                    signal: AbortSignal.timeout(this.timeoutMs),
                },
            );

            if (!response.ok) {
                return this.createResult(
                    'failed',
                    normalizedDomain,
                    `VirusTotal respondió con HTTP ${response.status}.`,
                );
            }

            const payload =
                await response.json() as VirusTotalResponse;

            const attributes = payload.data?.attributes;

            if (
                !attributes ||
                typeof attributes !== 'object'
            ) {
                return this.createResult(
                    'failed',
                    normalizedDomain,
                    'La respuesta de VirusTotal no contiene data.attributes.',
                );
            }

            return {
                status: 'completed',
                domain: normalizedDomain,

                stats: this.extractStats(
                    attributes.last_analysis_stats,
                ),

                communityReputation: this.toFiniteNumber(
                    attributes.reputation,
                ),

                categories: this.extractCategories(
                    attributes.categories,
                ),

                creationDate: this.formatCreationDate(
                    attributes.creation_date,
                ),

                alertEngines: this.extractAlertEngines(
                    attributes.last_analysis_results,
                ),

                error: null,
            };

        } catch (error: unknown) {
            const message = error instanceof Error
                ? error.message
                : String(error);

            return this.createResult(
                'failed',
                normalizedDomain,
                `No se pudo consultar VirusTotal: ${message}`,
            );
        }
    }

    private normalizeDomain(domain: string): string {
        if (
            typeof domain !== 'string' ||
            domain.trim().length === 0
        ) {
            throw new Error(
                'El dominio es obligatorio para consultar VirusTotal.',
            );
        }

        return domain
            .trim()
            .toLowerCase()
            .replace(/\.$/, '');
    }

    private extractStats(
        stats?: Record<string, unknown>,
    ): VirusTotalStats {
        return {
            malicious: this.toCount(stats?.malicious),
            suspicious: this.toCount(stats?.suspicious),
            harmless: this.toCount(stats?.harmless),
            undetected: this.toCount(stats?.undetected),
            timeout: this.toCount(stats?.timeout),
        };
    }

    private extractCategories(
        categories?: Record<string, unknown>,
    ): string[] {
        if (!categories) {
            return ['Sin clasificar'];
        }

        const values = Object.values(categories)
            .filter((value): value is string =>
                typeof value === 'string' &&
                value.trim().length > 0,
            );

        return values.length > 0
            ? values
            : ['Sin clasificar'];
    }

    private extractAlertEngines(
        results?: Record<string, VirusTotalVendorResult>,
    ): VirusTotalAlertEngine[] {
        if (!results) {
            return [];
        }

        const alerts: VirusTotalAlertEngine[] = [];

        for (const [engine, result] of Object.entries(results)) {
            if (
                result.category !== 'malicious' &&
                result.category !== 'suspicious'
            ) {
                continue;
            }

            alerts.push({
                engine,

                result: typeof result.result === 'string'
                    ? result.result
                    : result.category,

                category: result.category,
            });
        }

        return alerts;
    }

    private formatCreationDate(value: unknown): string {
        if (
            typeof value !== 'number' ||
            !Number.isFinite(value) ||
            value === 0
        ) {
            return 'No disponible';
        }

        const date = new Date(value * 1000);

        if (Number.isNaN(date.getTime())) {
            return 'No disponible';
        }

        return date.toISOString().slice(0, 10);
    }

    private toCount(value: unknown): number {
        if (
            typeof value !== 'number' ||
            !Number.isFinite(value)
        ) {
            return 0;
        }

        return Math.max(0, Math.floor(value));
    }

    private toFiniteNumber(value: unknown): number {
        return (
            typeof value === 'number' &&
            Number.isFinite(value)
        )
            ? value
            : 0;
    }

    private createResult(
        status: VirusTotalAnalysisResult['status'],
        domain: string,
        error: string | null,
    ): VirusTotalAnalysisResult {
        return {
            status,
            domain,
            stats: { ...DEFAULT_STATS },
            communityReputation: 0,
            categories: ['Sin clasificar'],
            creationDate: 'No disponible',
            alertEngines: [],
            error,
        };
    }
}

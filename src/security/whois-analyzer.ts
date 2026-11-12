
import { RdapInspector } from '../services/rdap-inspector';

export interface WhoisFinding {
    title: string;
    severity: 'low' | 'medium' | 'high';
    description: string;
}

export interface WhoisAnalysisResult {
    status: 'completed' | 'failed';
    domain: string;
    creationDate: string | null;
    expirationDate: string | null;
    updatedDate: string | null;
    registrar: string | null;
    domainAgeDays: number;
    daysUntilExpiration: number;
    findings: WhoisFinding[];
    error: string | null;
}

interface WhoisAnalyzerOptions {
    rdapInspector: RdapInspector;
    now?: () => Date;
}

export class WhoisAnalyzer {
    private readonly rdapInspector: RdapInspector;

    private readonly now: () => Date;

    constructor(options: WhoisAnalyzerOptions) {
        this.rdapInspector = options.rdapInspector;
        this.now = options.now ?? (() => new Date());
    }

    async analyze(
        domain: string,
    ): Promise<WhoisAnalysisResult> {
        try {
            const rdapResult =
                await this.rdapInspector.inspect(domain);

            const currentDate = this.now();

            const creationDate =
                this.parseDate(rdapResult.creationDate);

            const expirationDate =
                this.parseDate(rdapResult.expirationDate);

            const domainAgeDays = creationDate
                ? this.calculateDaysDifference(
                    creationDate,
                    currentDate,
                )
                : 0;

            const daysUntilExpiration = expirationDate
                ? this.calculateDaysDifference(
                    currentDate,
                    expirationDate,
                )
                : 0;

            return {
                status: 'completed',
                domain: rdapResult.domain,
                creationDate: rdapResult.creationDate,
                expirationDate: rdapResult.expirationDate,
                updatedDate: rdapResult.updatedDate,
                registrar: rdapResult.registrar,
                domainAgeDays,
                daysUntilExpiration,
                findings: this.createFindings(
                    daysUntilExpiration,
                ),
                error: null,
            };
        } catch (error: unknown) {
            return {
                status: 'failed',
                domain,
                creationDate: null,
                expirationDate: null,
                updatedDate: null,
                registrar: null,
                domainAgeDays: 0,
                daysUntilExpiration: 0,
                findings: [],
                error: this.formatError(error),
            };
        }
    }

    private parseDate(
        value: string | null,
    ): Date | null {
        if (!value) {
            return null;
        }

        const date = new Date(value);

        if (Number.isNaN(date.getTime())) {
            return null;
        }

        return date;
    }

    private calculateDaysDifference(
        startDate: Date,
        endDate: Date,
    ): number {
        const millisecondsPerDay =
            1000 * 60 * 60 * 24;

        return Math.floor(
            (
                endDate.getTime()
                - startDate.getTime()
            ) / millisecondsPerDay,
        );
    }

    private createFindings(
        daysUntilExpiration: number,
    ): WhoisFinding[] {
        // Equivalente a la condición Python:
        // 0 < dias_para_vencer < 30

        if (
            daysUntilExpiration > 0
            && daysUntilExpiration < 30
        ) {
            return [{
                title: 'Dominio próximo a vencer',
                severity: 'medium',
                description:
                    `Dominio próximo a vencer en WHOIS (${daysUntilExpiration} días restantes).`,
            }];
        }

        return [];
    }

    private formatError(error: unknown): string {
        const message = error instanceof Error
            ? error.message
            : String(error);

        return `No se pudo consultar WHOIS: ${message}`;
    }
}

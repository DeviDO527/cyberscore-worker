
import pino from 'pino';

import { loadConfig } from './config/env';

import {
    checkDatabaseConnection,
    closeDatabaseConnection,
    pool,
} from './database/pool';

import { EvaluationRepository } from './jobs/evaluation.repository';
import { EvaluationResultRepository } from './jobs/evaluation-result.repository';
import { WorkerProcessor } from './jobs/worker-processor';

import { NetworkTargetValidator } from './security/network-target-validator';

import { DnsAnalyzer } from './security/dns-analyzer';
import { TlsAnalyzer } from './security/tls-analyzer';
import { HeadersAnalyzer } from './security/headers-analyzer';
import { SecurityAnalyzer } from './security/security-analyzer';
import { WhoisAnalyzer } from './security/whois-analyzer';
import { VirusTotalAnalyzer } from './security/virustotal-analyzer';
import { NmapAnalyzer } from './security/nmap-analyzer';

import { Resolver } from 'node:dns/promises';
import { HttpInspector } from './services/http-inspector';
import { TlsInspector } from './services/tls-inspector';
import { RdapInspector } from './services/rdap-inspector';
import { NmapInspector } from './services/nmap-inspector';

import { calculateEvaluationScore } from './scoring/cyberscore-calculator';

// =====================================================
// CONFIGURACIÓN
// =====================================================

const config = loadConfig();

const logger = pino({
    level: config.logLevel,
});

// =====================================================
// UTILIDADES
// =====================================================

function sleep(milliseconds: number): Promise<void> {
    return new Promise(resolve => {
        setTimeout(resolve, milliseconds);
    });
}

// =====================================================
// INICIALIZACIÓN DEL WORKER
// =====================================================

export async function main(
    sleepFn: (milliseconds: number) => Promise<void> = sleep,
): Promise<void> {
    let shutdownRequested = false;

    process.once('SIGINT', () => {
        shutdownRequested = true;
        logger.info('Señal SIGINT recibida. Deteniendo worker...');
    });

    process.once('SIGTERM', () => {
        shutdownRequested = true;
        logger.info('Señal SIGTERM recibida. Deteniendo worker...');
    });

    try {
        // 1. Comprobar conexión MySQL.
        await checkDatabaseConnection();

        logger.info('Conexión a MySQL establecida.');

        // 2. Crear repositorios.
        const evaluationRepository =
            new EvaluationRepository(pool);

        const evaluationResultRepository =
            new EvaluationResultRepository(pool);

        // 3. Configurar autorización de dominios.
        const targetValidator = new NetworkTargetValidator(
            config.allowedDomains,
            undefined,
            {
                allowAnyPublicDomain: config.allowAnyPublicDomain,
            },
        );

        const nmapInspector = new NmapInspector(
            targetValidator,
            undefined,
            { defaultMode: config.nmap.scanMode },
        );

        // =====================================================
        // 4. CREAR INSPECTORES
        // =====================================================

        const dnsResolver = new Resolver();

        const httpInspector = new HttpInspector(
            targetValidator,
        );

        const tlsInspector = new TlsInspector(
            targetValidator,
        );

        const rdapInspector = new RdapInspector();

        // =====================================================
        // 5. CREAR ANALIZADORES
        // =====================================================

        const dnsAnalyzer = new DnsAnalyzer(
            dnsResolver,
        );

        const tlsAnalyzer = new TlsAnalyzer(
            tlsInspector,
        );

        const headersAnalyzer = new HeadersAnalyzer(
            httpInspector,
        );

        const whoisAnalyzer = new WhoisAnalyzer({
            rdapInspector,
        });

        const virusTotalAnalyzer = new VirusTotalAnalyzer({
            apiKey: config.virusTotalApiKey ?? '',
        });

        const nmapAnalyzer = new NmapAnalyzer();

        const analyzeNmapForDomain = async (
            domain: string,
            explicitlyAuthorized: boolean,
        ) => {
            if (!explicitlyAuthorized) {
                return {
                    status: 'skipped',
                    authorized: false,
                    scope: domain,
                    mode: config.nmap.scanMode,
                    openPorts: [],
                    reason: 'domain_not_explicitly_authorized',
                };
            }

            try {
                const inspection = await nmapInspector.inspect(
                    domain,
                    {
                        authorized: true,
                        scope: domain,
                    },
                );

                return await nmapAnalyzer.analyze(inspection);
            } catch (error: unknown) {
                const message = error instanceof Error
                    ? error.message.slice(0, 500)
                    : 'Error desconocido durante la inspección Nmap.';

                logger.warn(
                    {
                        domain,
                        error: message,
                    },
                    'La inspección Nmap falló; continúa el resto de la evaluación.',
                );

                return {
                    status: 'failed',
                    authorized: true,
                    scope: domain,
                    mode: config.nmap.scanMode,
                    openPorts: [],
                    error: message,
                };
            }
        };

        // 6. Crear orquestador de seguridad.
        const securityAnalyzer = new SecurityAnalyzer({
            dnsAnalyzer,
            tlsAnalyzer,
            headersAnalyzer,
        });

        // =====================================================
        // 7. CREAR PROCESADOR
        // =====================================================

        const workerProcessor = new WorkerProcessor(
            evaluationRepository,
            evaluationResultRepository,

            async evaluation => {
                // WorkerProcessor solo entrega evaluaciones cuyo dominio
                // coincide con un activo autorizado de esta PyME en MySQL.
                targetValidator.authorizeRegisteredDomain(evaluation.domain);

                // Ejecutar los análisis independientes en paralelo.
                const [
                    securityResult,
                    whoisResult,
                    virusTotalResult,
                    nmapResult,
                ] = await Promise.all([
                    securityAnalyzer.analyze(evaluation.domain),
                    whoisAnalyzer.analyze(evaluation.domain),
                    virusTotalAnalyzer.analyze(evaluation.domain),
                    analyzeNmapForDomain(
                        evaluation.domain,
                        evaluation.domainAuthorized,
                    ),
                ]);

                // Conservar los resultados detallados de cada análisis.
                const layersSummary = {
                    ...securityResult.layersSummary,

                    dnsRecords: securityResult.dnsRecords,

                    whois: {
                        status: whoisResult.status,
                        domain: whoisResult.domain,
                        creationDate: whoisResult.creationDate,
                        expirationDate: whoisResult.expirationDate,
                        updatedDate: whoisResult.updatedDate,
                        registrar: whoisResult.registrar,
                        domainAgeDays: whoisResult.domainAgeDays,
                        daysUntilExpiration: whoisResult.daysUntilExpiration,
                        error: whoisResult.error,
                    },

                    virusTotal: {
                        status: virusTotalResult.status,
                        domain: virusTotalResult.domain,
                        stats: virusTotalResult.stats,
                        communityReputation:
                            virusTotalResult.communityReputation,
                        categories: virusTotalResult.categories,
                        creationDate: virusTotalResult.creationDate,
                        alertEngines: virusTotalResult.alertEngines,
                        error: virusTotalResult.error,
                    },

                    nmap: nmapResult,
                };

                // Calcular el CyberScore con penalizaciones independientes.
                const scoringResult = calculateEvaluationScore({
                    findings: securityResult.findings,
                    nmap: nmapResult,

                    whois: {
                        status: whoisResult.status,
                        daysUntilExpiration:
                            whoisResult.daysUntilExpiration,
                    },

                    virusTotal: {
                        status: virusTotalResult.status,
                        stats: virusTotalResult.stats,
                    },

                    businessContext: {
                        monthlyRevenue: evaluation.monthlyRevenue,
                        operatingHours: evaluation.operatingHours,
                        currency: evaluation.currency,
                    },

                    layersSummary,
                });

                logger.info(
                    {
                        evaluationId: evaluation.id,
                        domain: evaluation.domain,
                        findings: securityResult.findings.length,
                        score: scoringResult.score,
                        baseScore: scoringResult.baseScore,
                        whoisPenalty: scoringResult.whoisPenalty,
                        virusTotalPenalty:
                            scoringResult.virusTotalPenalty,
                        nmapPenalty: scoringResult.nmapPenalty,
                        virusTotalStatus: virusTotalResult.status,
                        level: scoringResult.level,
                    },
                    'Análisis y cálculo CyberScore completados.',
                );

                return {
                    score: scoringResult.score,
                    level: scoringResult.level,
                    layersSummary: scoringResult.layersSummary,
                    findings: securityResult.findings,
                };
            },

            logger,
        );

        logger.info(
            {
                environment: config.nodeEnv,
                demoMode: config.allowAnyPublicDomain,
                batchSize: config.worker.batchSize,
                pollIntervalMs: config.worker.pollIntervalMs,
                virusTotalConfigured: Boolean(
                    config.virusTotalApiKey,
                ),
                nmapMode: config.nmap.scanMode,
            },
            'CyberScore Worker iniciado correctamente.',
        );

        // =================================================
        // CICLO PRINCIPAL
        // =================================================

        while (!shutdownRequested) {
            let processedAny = false;

            try {
                for (
                    let index = 0;
                    index < config.worker.batchSize &&
                    !shutdownRequested;
                    index++
                ) {
                    const processed =
                        await workerProcessor.processNext();

                    if (!processed) {
                        break;
                    }

                    processedAny = true;
                }
            } catch (error) {
                logger.error(
                    {
                        error:
                            error instanceof Error
                                ? error.message
                                : 'Error desconocido.',
                    },
                    'Error durante el ciclo de procesamiento.',
                );
            }

            // Esperar únicamente cuando no existan evaluaciones.
            if (!processedAny && !shutdownRequested) {
                await sleepFn(config.worker.pollIntervalMs); // NOSONAR - El worker debe esperar antes de consultar nuevamente la cola vacía.
            }
        }

        logger.info('Worker detenido correctamente.');

    } finally {
        await closeDatabaseConnection();
        logger.info('Conexión MySQL cerrada.');
    }
}

// =====================================================
// ARRANQUE
// =====================================================

function handleStartupFailure(error: unknown): void {
    logger.fatal(
        {
            error:
                error instanceof Error
                    ? error.message
                    : 'Error desconocido al iniciar el worker.',
        },
        'No fue posible iniciar CyberScore Worker.',
    );

    process.exitCode = 1;
}

export function startWorker(): Promise<void> {
    return main().catch(handleStartupFailure);
}

export function bootstrap(
    isMainModule = require.main === module,
): Promise<void> | undefined {
    if (!isMainModule) {
        return undefined;
    }

    return startWorker();
}

if (require.main === module) {
    bootstrap()?.catch(handleStartupFailure);
}

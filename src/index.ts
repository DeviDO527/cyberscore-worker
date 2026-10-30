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

import { Resolver } from 'node:dns/promises';
import { HttpInspector } from './services/http-inspector';
import { TlsInspector } from './services/tls-inspector';

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

async function main(): Promise<void> {
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

        // =====================================================
// 4. CREAR INSPECTORES Y RESOLVER DNS
// =====================================================

        const dnsResolver = new Resolver();

        const httpInspector = new HttpInspector(
            targetValidator,
        );

        const tlsInspector = new TlsInspector(
            targetValidator,
        );

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

        // 6. Crear orquestador de seguridad.
        const securityAnalyzer = new SecurityAnalyzer({
            dnsAnalyzer,
            tlsAnalyzer,
            headersAnalyzer,
        });

        // 7. Crear procesador.
        const workerProcessor = new WorkerProcessor(
            evaluationRepository,
            evaluationResultRepository,

            async evaluation => {
                // Ejecutar los análisis DNS, TLS y HTTP.
                const securityResult =
                    await securityAnalyzer.analyze(evaluation.domain);

                // Incorporar los registros DNS al resumen
                // para conservarlos en MySQL.
                const layersSummary = {
                    ...securityResult.layersSummary,
                    dnsRecords: securityResult.dnsRecords,
                };

                // Calcular el CyberScore.
                const scoringResult = calculateEvaluationScore({
                    findings: securityResult.findings,

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
                await sleep(config.worker.pollIntervalMs);
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

main().catch(error => {
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
});
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

type SignalName = 'SIGINT' | 'SIGTERM';

interface WorkerConfig {
    nodeEnv: string;
    logLevel: string;
    allowedDomains: string[];
    allowAnyPublicDomain: boolean;
    worker: {
        batchSize: number;
        pollIntervalMs: number;
    };
}

interface WorkerEntryPoint {
    main(sleepFn?: (milliseconds: number) => Promise<void>): Promise<void>;
    startWorker(): Promise<void>;
    bootstrap(isMainModule?: boolean): Promise<void> | undefined;
}

describe('arranque de CyberScore Worker', () => {
    let config: WorkerConfig;
    let logger: {
        info: any;
        error: any;
        fatal: any;
    };
    let checkDatabaseConnection: any;
    let closeDatabaseConnection: any;
    let processNext: any;
    let analyzeSecurity: any;
    let calculateEvaluationScore: any;
    let analyzeEvaluation: ((evaluation: any) => Promise<any>) | undefined;
    let signalHandlers: Record<SignalName, Array<() => void>>;
    let workerEntryPoint: WorkerEntryPoint;
    let originalExitCode: string | number | null | undefined;

    const emitSignal = (signal: SignalName): void => {
        for (const handler of signalHandlers[signal]) {
            handler();
        }
    };

    beforeEach(() => {
        jest.resetModules();

        originalExitCode = process.exitCode;
        config = {
            nodeEnv: 'test',
            logLevel: 'silent',
            allowedDomains: ['example.com'],
            allowAnyPublicDomain: false,
            worker: {
                batchSize: 3,
                pollIntervalMs: 5,
            },
        };

        logger = {
            info: jest.fn(),
            error: jest.fn(),
            fatal: jest.fn(),
        };
        checkDatabaseConnection = jest.fn(async () => undefined);
        closeDatabaseConnection = jest.fn(async () => undefined);
        signalHandlers = { SIGINT: [], SIGTERM: [] };
        analyzeEvaluation = undefined;
        analyzeSecurity = jest.fn(async () => ({
            layersSummary: { tls: 'secure' },
            dnsRecords: { a: ['203.0.113.10'] },
            findings: [],
        }));
        calculateEvaluationScore = jest.fn().mockReturnValue({
            score: 87,
            level: 'A',
            layersSummary: { overall: 'secure' },
        });

        processNext = jest.fn().mockImplementation(async () => {
            emitSignal('SIGINT');
            return false;
        });

        jest.doMock('pino', () => ({
            __esModule: true,
            default: jest.fn(() => logger),
        }));
        jest.doMock('../src/config/env', () => ({
            loadConfig: jest.fn(() => config),
        }));
        jest.doMock('../src/database/pool', () => ({
            checkDatabaseConnection,
            closeDatabaseConnection,
            pool: {},
        }));
        jest.doMock('../src/jobs/evaluation.repository', () => ({
            EvaluationRepository: jest.fn(() => ({})),
        }));
        jest.doMock('../src/jobs/evaluation-result.repository', () => ({
            EvaluationResultRepository: jest.fn(() => ({})),
        }));
        jest.doMock('../src/jobs/worker-processor', () => ({
            WorkerProcessor: jest.fn(
                (_evaluationRepository: unknown, _resultRepository: unknown, callback: (evaluation: any) => Promise<any>) => {
                    analyzeEvaluation = callback;
                    return { processNext };
                },
            ),
        }));
        jest.doMock('../src/security/network-target-validator', () => ({
            NetworkTargetValidator: jest.fn(() => ({})),
        }));
        jest.doMock('../src/security/dns-analyzer', () => ({
            DnsAnalyzer: jest.fn(() => ({})),
        }));
        jest.doMock('../src/security/tls-analyzer', () => ({
            TlsAnalyzer: jest.fn(() => ({})),
        }));
        jest.doMock('../src/security/headers-analyzer', () => ({
            HeadersAnalyzer: jest.fn(() => ({})),
        }));
        jest.doMock('../src/security/security-analyzer', () => ({
            SecurityAnalyzer: jest.fn(() => ({ analyze: analyzeSecurity })),
        }));
        jest.doMock('../src/services/http-inspector', () => ({
            HttpInspector: jest.fn(() => ({})),
        }));
        jest.doMock('../src/services/tls-inspector', () => ({
            TlsInspector: jest.fn(() => ({})),
        }));
        jest.doMock('../src/scoring/cyberscore-calculator', () => ({
            calculateEvaluationScore: (...args: unknown[]) =>
                calculateEvaluationScore(...args),
        }));

        jest.spyOn(process, 'once').mockImplementation(((
            event: string | symbol,
            listener: (...args: any[]) => void,
        ) => {
            if (event === 'SIGINT' || event === 'SIGTERM') {
                signalHandlers[event].push(listener as () => void);
            }
            return process;
        }) as any);

        workerEntryPoint = require('../src/index') as WorkerEntryPoint;
    });

    afterEach(() => {
        jest.restoreAllMocks();
        jest.useRealTimers();
        process.exitCode = originalExitCode;
    });

    it('inicializa los analizadores, procesa una evaluación y espera cuando la cola está vacía', async () => {
        expect(checkDatabaseConnection).not.toHaveBeenCalled();

        const evaluation = {
            id: 'evaluation-1',
            pymeId: 'pyme-1',
            domain: 'example.com',
            monthlyRevenue: 1000000,
            operatingHours: 160,
            currency: 'COP',
        };

        processNext.mockImplementationOnce(async () => {
            const result = await analyzeEvaluation!(evaluation);
            expect(result).toEqual({
                score: 87,
                level: 'A',
                layersSummary: { overall: 'secure' },
                findings: [],
            });
            return false;
        });

        const sleep = jest.fn(async (_milliseconds: number) => emitSignal('SIGINT'));

        await workerEntryPoint.main(sleep);

        expect(checkDatabaseConnection).toHaveBeenCalledTimes(1);
        expect(analyzeSecurity).toHaveBeenCalledWith('example.com');
        expect(calculateEvaluationScore).toHaveBeenCalledWith(
            expect.objectContaining({
                findings: [],
                businessContext: {
                    monthlyRevenue: 1000000,
                    operatingHours: 160,
                    currency: 'COP',
                },
                layersSummary: {
                    tls: 'secure',
                    dnsRecords: { a: ['203.0.113.10'] },
                },
            }),
        );
        expect(sleep).toHaveBeenCalledWith(5);
        expect(closeDatabaseConnection).toHaveBeenCalledTimes(1);
    });

    it('detiene el lote al recibir SIGTERM y omite la espera tras procesar trabajos', async () => {
        processNext
            .mockResolvedValueOnce(true)
            .mockImplementationOnce(async () => {
                emitSignal('SIGTERM');
                return true;
            });
        const sleep = jest.fn(async () => undefined);

        await workerEntryPoint.main(sleep);

        expect(processNext).toHaveBeenCalledTimes(2);
        expect(sleep).not.toHaveBeenCalled();
        expect(logger.info).toHaveBeenCalledWith(
            'Señal SIGTERM recibida. Deteniendo worker...',
        );
    });

    it('respeta el tamaño máximo del lote antes de consultar la siguiente evaluación', async () => {
        config.worker.batchSize = 1;
        processNext
            .mockResolvedValueOnce(true)
            .mockImplementationOnce(async () => {
                emitSignal('SIGINT');
                return false;
            });

        await workerEntryPoint.main(jest.fn(async () => undefined));

        expect(processNext).toHaveBeenCalledTimes(2);
    });

    it('ejecuta la espera configurada cuando usa el temporizador predeterminado', async () => {
        processNext.mockResolvedValueOnce(false);
        const timer = jest.spyOn(global, 'setTimeout').mockImplementation(((
            callback: (...args: any[]) => void,
        ) => {
            emitSignal('SIGINT');
            callback();
            return {} as NodeJS.Timeout;
        }) as any);

        await workerEntryPoint.main();

        expect(timer).toHaveBeenCalledWith(expect.any(Function), 5);
    });

    it.each([
        {
            error: new Error('fallo durante el procesamiento'),
            message: 'fallo durante el procesamiento',
        },
        {
            error: 'fallo sin objeto Error',
            message: 'Error desconocido.',
        },
    ])('registra errores de procesamiento y continúa el cierre', async ({ error, message }) => {
        processNext.mockImplementationOnce(async () => {
            emitSignal('SIGINT');
            throw error;
        });

        await workerEntryPoint.main(jest.fn(async () => undefined));

        expect(logger.error).toHaveBeenCalledWith(
            { error: message },
            'Error durante el ciclo de procesamiento.',
        );
        expect(closeDatabaseConnection).toHaveBeenCalledTimes(1);
    });

    it.each([
        {
            error: new Error('fallo de conexión'),
            message: 'fallo de conexión',
            useBootstrap: true,
        },
        {
            error: 'fallo sin objeto Error',
            message: 'Error desconocido al iniciar el worker.',
            useBootstrap: false,
        },
    ])('registra fallos de inicio y asigna código de salida 1', async ({ error, message, useBootstrap }) => {
        checkDatabaseConnection.mockRejectedValueOnce(error);

        if (useBootstrap) {
            await workerEntryPoint.bootstrap(true);
        } else {
            await workerEntryPoint.startWorker();
        }

        expect(logger.fatal).toHaveBeenCalledWith(
            { error: message },
            'No fue posible iniciar CyberScore Worker.',
        );
        expect(process.exitCode).toBe(1);
        expect(closeDatabaseConnection).toHaveBeenCalledTimes(1);
    });
});

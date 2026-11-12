
import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';

type SignalName = 'SIGINT' | 'SIGTERM';

interface WorkerConfig {
    nodeEnv: string;
    logLevel: string;
    allowedDomains: string[];
    allowAnyPublicDomain: boolean;
    nmap: {
        scanMode: 'standard' | 'deep';
    };
    virusTotalApiKey?: string;
    worker: {
        batchSize: number;
        pollIntervalMs: number;
    };
}

interface WorkerEntryPoint {
    main(
        sleepFn?: (milliseconds: number) => Promise<void>,
    ): Promise<void>;

    startWorker(): Promise<void>;

    bootstrap(
        isMainModule?: boolean,
    ): Promise<void> | undefined;
}

describe('arranque de CyberScore Worker', () => {
    let config: WorkerConfig;

    let logger: {
        info: any;
        warn: any;
        error: any;
        fatal: any;
    };

    let checkDatabaseConnection: any;
    let closeDatabaseConnection: any;
    let processNext: any;

    let analyzeSecurity: any;
    let analyzeWhois: any;
    let analyzeVirusTotal: any;
    let inspectNmap: any;
    let analyzeNmap: any;
    let nmapInspectorOptions: any;

    let calculateEvaluationScore: any;

    let analyzeEvaluation:
        | ((evaluation: any) => Promise<any>)
        | undefined;

    let signalHandlers: Record<
        SignalName,
        Array<() => void>
    >;

    let workerEntryPoint: WorkerEntryPoint;

    let originalExitCode:
        | string
        | number
        | null
        | undefined;

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
            nmap: {
                scanMode: 'standard',
            },
            virusTotalApiKey: 'a'.repeat(64),

            worker: {
                batchSize: 3,
                pollIntervalMs: 5,
            },
        };

        logger = {
            info: jest.fn(),
            warn: jest.fn(),
            error: jest.fn(),
            fatal: jest.fn(),
        };

        checkDatabaseConnection = jest.fn(
            async () => undefined,
        );

        closeDatabaseConnection = jest.fn(
            async () => undefined,
        );

        signalHandlers = {
            SIGINT: [],
            SIGTERM: [],
        };

        analyzeEvaluation = undefined;

        analyzeSecurity = jest.fn(async () => ({
            layersSummary: {
                tls: 'secure',
            },

            dnsRecords: {
                a: ['203.0.113.10'],
            },

            findings: [],
        }));

        analyzeWhois = jest.fn(async () => ({
            status: 'completed',
            domain: 'example.com',
            creationDate: '2020-01-01T00:00:00Z',
            expirationDate: '2027-01-01T00:00:00Z',
            updatedDate: null,
            registrar: 'Example Registrar',
            domainAgeDays: 2190,
            daysUntilExpiration: 365,
            findings: [],
            error: null,
        }));

        analyzeVirusTotal = jest.fn(async () => ({
            status: 'completed',
            domain: 'example.com',

            stats: {
                malicious: 2,
                suspicious: 1,
                harmless: 45,
                undetected: 8,
                timeout: 1,
            },

            communityReputation: -12,

            categories: ['technology'],

            creationDate: '2020-01-01',

            alertEngines: [
                {
                    engine: 'EngineA',
                    result: 'phishing',
                    category: 'malicious',
                },
            ],

            error: null,
        }));

        inspectNmap = jest.fn(async () => ({
            inspection: true,
        }));

        analyzeNmap = jest.fn(async () => ({
            status: 'completed',
            hostname: 'example.com',
            addresses: ['8.8.8.8'],
            mode: 'standard',
            authorization: {
                authorized: true,
                scope: 'example.com',
            },
            openPorts: [
                {
                    address: '8.8.8.8',
                    hostname: 'example.com',
                    port: 443,
                    protocol: 'TCP',
                    state: 'open',
                    service: 'https',
                    product: 'Example Server',
                    version: '1.0',
                    extraInfo: null,
                    serviceDetails: 'HTTPS (Example Server v1.0)',
                },
            ],
        }));
        nmapInspectorOptions = undefined;

        calculateEvaluationScore = jest.fn().mockReturnValue({
            score: 87,
            level: 'A',
            baseScore: 100,
            whoisPenalty: 0,
            virusTotalPenalty: 75,
            nmapPenalty: 0,
            layersSummary: {
                overall: 'secure',
            },
        });

        processNext = jest.fn().mockImplementation(
            async () => {
                emitSignal('SIGINT');
                return false;
            },
        );

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
                (
                    _evaluationRepository: unknown,
                    _resultRepository: unknown,
                    callback: (evaluation: any) => Promise<any>,
                ) => {
                    analyzeEvaluation = callback;

                    return {
                        processNext,
                    };
                },
            ),
        }));

        jest.doMock('../src/security/network-target-validator', () => ({
            NetworkTargetValidator: jest.fn(() => ({
                authorizeRegisteredDomain: jest.fn(),
            })),
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
            SecurityAnalyzer: jest.fn(() => ({
                analyze: analyzeSecurity,
            })),
        }));

        jest.doMock('../src/services/http-inspector', () => ({
            HttpInspector: jest.fn(() => ({})),
        }));

        jest.doMock('../src/services/tls-inspector', () => ({
            TlsInspector: jest.fn(() => ({})),
        }));

        jest.doMock('../src/services/rdap-inspector', () => ({
            RdapInspector: jest.fn(() => ({})),
        }));

        jest.doMock('../src/security/whois-analyzer', () => ({
            WhoisAnalyzer: jest.fn(() => ({
                analyze: analyzeWhois,
            })),
        }));

        jest.doMock('../src/security/virustotal-analyzer', () => ({
            VirusTotalAnalyzer: jest.fn(() => ({
                analyze: analyzeVirusTotal,
            })),
        }));

        jest.doMock('../src/services/nmap-inspector', () => ({
            NmapInspector: jest.fn(
                (
                    _targetValidator: unknown,
                    _processRunner: unknown,
                    options: unknown,
                ) => {
                    nmapInspectorOptions = options;

                    return {
                        inspect: inspectNmap,
                    };
                },
            ),
        }));

        jest.doMock('../src/security/nmap-analyzer', () => ({
            NmapAnalyzer: jest.fn(() => ({
                analyze: analyzeNmap,
            })),
        }));

        jest.doMock('../src/scoring/cyberscore-calculator', () => ({
            calculateEvaluationScore: (...args: unknown[]) =>
                calculateEvaluationScore(...args),
        }));

        jest.spyOn(
            process,
            'once',
        ).mockImplementation(((
            event: string | symbol,
            listener: (...args: any[]) => void,
        ) => {
            if (
                event === 'SIGINT' ||
                event === 'SIGTERM'
            ) {
                signalHandlers[event].push(
                    listener as () => void,
                );
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

    it(
        'inicializa los analizadores, procesa una evaluación y espera cuando la cola está vacía',
        async () => {
            expect(checkDatabaseConnection).not.toHaveBeenCalled();

            const evaluation = {
                id: 'evaluation-1',
                pymeId: 'pyme-1',
                domain: 'example.com',
                domainAuthorized: true,
                monthlyRevenue: 1000000,
                operatingHours: 160,
                currency: 'COP',
            };

            processNext.mockImplementationOnce(async () => {
                const result = await analyzeEvaluation!(
                    evaluation,
                );

                expect(result).toEqual({
                    score: 87,
                    level: 'A',
                    layersSummary: {
                        overall: 'secure',
                    },
                    findings: [],
                    nmap: expect.objectContaining({
                        status: 'completed',
                        openPorts: expect.arrayContaining([
                            expect.objectContaining({
                                port: 443,
                                protocol: 'TCP',
                                serviceDetails: 'HTTPS (Example Server v1.0)',
                            }),
                        ]),
                    }),
                });

                return false;
            });

            const sleep = jest.fn(
                async (_milliseconds: number) => {
                    emitSignal('SIGINT');
                },
            );

            await workerEntryPoint.main(sleep);

            expect(checkDatabaseConnection).toHaveBeenCalledTimes(1);

            expect(analyzeSecurity).toHaveBeenCalledWith(
                'example.com',
            );

            expect(analyzeWhois).toHaveBeenCalledWith(
                'example.com',
            );

            expect(analyzeVirusTotal).toHaveBeenCalledWith(
                'example.com',
            );

            expect(nmapInspectorOptions).toEqual({
                defaultMode: 'standard',
            });
            expect(inspectNmap).toHaveBeenCalledWith(
                'example.com',
                {
                    authorized: true,
                    scope: 'example.com',
                },
            );
            expect(analyzeNmap).toHaveBeenCalledWith({
                inspection: true,
            });

            expect(calculateEvaluationScore).toHaveBeenCalledWith(
                expect.objectContaining({
                    findings: [],

                    whois: {
                        status: 'completed',
                        daysUntilExpiration: 365,
                    },

                    virusTotal: {
                        status: 'completed',

                        stats: {
                            malicious: 2,
                            suspicious: 1,
                            harmless: 45,
                            undetected: 8,
                            timeout: 1,
                        },
                    },

                    businessContext: {
                        monthlyRevenue: 1000000,
                        operatingHours: 160,
                        currency: 'COP',
                    },

                    layersSummary: expect.objectContaining({
                        tls: 'secure',

                        nmap: expect.objectContaining({
                            status: 'completed',
                            mode: 'standard',
                            openPorts: expect.arrayContaining([
                                expect.objectContaining({
                                    port: 443,
                                    service: 'https',
                                }),
                            ]),
                        }),

                        dnsRecords: {
                            a: ['203.0.113.10'],
                        },

                        whois: expect.objectContaining({
                            status: 'completed',
                            domain: 'example.com',
                            registrar: 'Example Registrar',
                            daysUntilExpiration: 365,
                        }),

                        virusTotal: {
                            status: 'completed',
                            domain: 'example.com',

                            stats: {
                                malicious: 2,
                                suspicious: 1,
                                harmless: 45,
                                undetected: 8,
                                timeout: 1,
                            },

                            communityReputation: -12,
                            categories: ['technology'],
                            creationDate: '2020-01-01',

                            alertEngines: [
                                {
                                    engine: 'EngineA',
                                    result: 'phishing',
                                    category: 'malicious',
                                },
                            ],

                            error: null,
                        },
                    }),
                }),
            );

            expect(sleep).toHaveBeenCalledWith(5);

            expect(closeDatabaseConnection).toHaveBeenCalledTimes(1);
        },
    );

    it(
        'omite Nmap cuando el dominio no está autorizado en MySQL',
        async () => {
            config.allowedDomains = [];
            config.allowAnyPublicDomain = true;

            const evaluation = {
                id: 'evaluation-demo-domain',
                pymeId: 'pyme-1',
                domain: 'example.com',
                domainAuthorized: false,
                monthlyRevenue: 1000000,
                operatingHours: 160,
                currency: 'COP',
            };

            processNext.mockImplementationOnce(async () => {
                await analyzeEvaluation!(evaluation);
                return false;
            });

            await workerEntryPoint.main(
                jest.fn(async () => emitSignal('SIGINT')),
            );

            expect(inspectNmap).not.toHaveBeenCalled();
            expect(calculateEvaluationScore).toHaveBeenCalledWith(
                expect.objectContaining({
                    layersSummary: expect.objectContaining({
                        nmap: {
                            status: 'skipped',
                            authorized: false,
                            scope: 'example.com',
                            mode: 'standard',
                            openPorts: [],
                            reason: 'domain_not_explicitly_authorized',
                        },
                    }),
                }),
            );
        },
    );

    it(
        'registra el fallo de Nmap y termina el resto de la evaluación',
        async () => {
            inspectNmap.mockRejectedValueOnce(
                new Error('Nmap no está disponible'),
            );

            const evaluation = {
                id: 'evaluation-nmap-failure',
                pymeId: 'pyme-1',
                domain: 'example.com',
                domainAuthorized: true,
                monthlyRevenue: 1000000,
                operatingHours: 160,
                currency: 'COP',
            };

            processNext.mockImplementationOnce(async () => {
                const result = await analyzeEvaluation!(evaluation);

                expect(result.score).toBe(87);
                return false;
            });

            await workerEntryPoint.main(
                jest.fn(async () => emitSignal('SIGINT')),
            );

            expect(calculateEvaluationScore).toHaveBeenCalledWith(
                expect.objectContaining({
                    layersSummary: expect.objectContaining({
                        nmap: expect.objectContaining({
                            status: 'failed',
                            authorized: true,
                            error: 'Nmap no está disponible',
                        }),
                    }),
                }),
            );
            expect(logger.warn).toHaveBeenCalled();
        },
    );

    it(
        'continúa la evaluación sin penalización cuando la consulta WHOIS falla',
        async () => {
            analyzeWhois.mockResolvedValueOnce({
                status: 'failed',
                domain: 'example.com',
                creationDate: null,
                expirationDate: null,
                updatedDate: null,
                registrar: null,
                domainAgeDays: 0,
                daysUntilExpiration: 0,
                findings: [],
                error: 'No se pudo consultar WHOIS: servicio no disponible',
            });

            const evaluation = {
                id: 'evaluation-2',
                pymeId: 'pyme-1',
                domain: 'example.com',
                domainAuthorized: true,
                monthlyRevenue: 1000000,
                operatingHours: 160,
                currency: 'COP',
            };

            processNext.mockImplementationOnce(async () => {
                await analyzeEvaluation!(evaluation);
                return false;
            });

            await workerEntryPoint.main(
                jest.fn(async () => emitSignal('SIGINT')),
            );

            expect(analyzeWhois).toHaveBeenCalledWith(
                'example.com',
            );

            expect(calculateEvaluationScore).toHaveBeenCalledWith(
                expect.objectContaining({
                    whois: {
                        status: 'failed',
                        daysUntilExpiration: 0,
                    },
                }),
            );

            expect(closeDatabaseConnection).toHaveBeenCalledTimes(1);
        },
    );

    it(
        'continúa la evaluación cuando VirusTotal no está disponible',
        async () => {
            analyzeVirusTotal.mockResolvedValueOnce({
                status: 'unavailable',
                domain: 'example.com',

                stats: {
                    malicious: 0,
                    suspicious: 0,
                    harmless: 0,
                    undetected: 0,
                    timeout: 0,
                },

                communityReputation: 0,
                categories: ['Sin clasificar'],
                creationDate: 'No disponible',
                alertEngines: [],
                error: 'VIRUSTOTAL_API_KEY no está configurada.',
            });

            const evaluation = {
                id: 'evaluation-3',
                pymeId: 'pyme-1',
                domain: 'example.com',
                domainAuthorized: true,
                monthlyRevenue: 1000000,
                operatingHours: 160,
                currency: 'COP',
            };

            processNext.mockImplementationOnce(async () => {
                await analyzeEvaluation!(evaluation);
                return false;
            });

            await workerEntryPoint.main(
                jest.fn(async () => emitSignal('SIGINT')),
            );

            expect(analyzeVirusTotal).toHaveBeenCalledWith(
                'example.com',
            );

            expect(calculateEvaluationScore).toHaveBeenCalledWith(
                expect.objectContaining({
                    virusTotal: {
                        status: 'unavailable',

                        stats: {
                            malicious: 0,
                            suspicious: 0,
                            harmless: 0,
                            undetected: 0,
                            timeout: 0,
                        },
                    },
                }),
            );

            expect(closeDatabaseConnection).toHaveBeenCalledTimes(1);
        },
    );

    it(
        'detiene el lote al recibir SIGTERM y omite la espera tras procesar trabajos',
        async () => {
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
        },
    );

    it(
        'respeta el tamaño máximo del lote antes de consultar la siguiente evaluación',
        async () => {
            config.worker.batchSize = 1;

            processNext
                .mockResolvedValueOnce(true)
                .mockImplementationOnce(async () => {
                    emitSignal('SIGINT');
                    return false;
                });

            await workerEntryPoint.main(
                jest.fn(async () => undefined),
            );

            expect(processNext).toHaveBeenCalledTimes(2);
        },
    );

    it(
        'ejecuta la espera configurada cuando usa el temporizador predeterminado',
        async () => {
            processNext.mockResolvedValueOnce(false);

            const timer = jest.spyOn(
                global,
                'setTimeout',
            ).mockImplementation(((
                callback: (...args: any[]) => void,
            ) => {
                emitSignal('SIGINT');
                callback();

                return {} as NodeJS.Timeout;
            }) as any);

            await workerEntryPoint.main();

            expect(timer).toHaveBeenCalledWith(
                expect.any(Function),
                5,
            );
        },
    );

    it.each([
        {
            error: new Error('fallo durante el procesamiento'),
            message: 'fallo durante el procesamiento',
        },
        {
            error: 'fallo sin objeto Error',
            message: 'Error desconocido.',
        },
    ])(
        'registra errores de procesamiento y continúa el cierre',
        async ({ error, message }) => {
            processNext.mockImplementationOnce(async () => {
                emitSignal('SIGINT');
                throw error;
            });

            await workerEntryPoint.main(
                jest.fn(async () => undefined),
            );

            expect(logger.error).toHaveBeenCalledWith(
                { error: message },
                'Error durante el ciclo de procesamiento.',
            );

            expect(closeDatabaseConnection).toHaveBeenCalledTimes(1);
        },
    );

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
    ])(
        'registra fallos de inicio y asigna código de salida 1',
        async ({ error, message, useBootstrap }) => {
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
        },
    );

    it('no arranca el worker cuando bootstrap indica que no es el módulo principal', () => {
        expect(workerEntryPoint.bootstrap(false)).toBeUndefined();
        expect(checkDatabaseConnection).not.toHaveBeenCalled();
    });
});

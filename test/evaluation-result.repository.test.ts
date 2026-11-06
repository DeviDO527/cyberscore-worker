import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import type { Pool } from 'mysql2/promise';
import { EvaluationResultRepository } from '../src/jobs/evaluation-result.repository';

describe('EvaluationResultRepository', () => {
    type MockConnection = {
    beginTransaction: jest.Mock<() => Promise<void>>;
    execute: jest.Mock<
    (sql: string, values?: unknown[]) => Promise<[unknown, unknown]>
    >;
    commit: jest.Mock<() => Promise<void>>;
    rollback: jest.Mock<() => Promise<void>>;
    release: jest.Mock<() => void>;
    };

    type MockPool = {
        getConnection: jest.Mock<() => Promise<MockConnection>>;
    };

    let repository: EvaluationResultRepository;
    let mockConnection: MockConnection;
    let mockPool: MockPool;

    beforeEach(() => {
        mockConnection = {
            beginTransaction: jest.fn<() => Promise<void>>().mockResolvedValue(),
            execute: jest.fn<
                (sql: string, values?: unknown[]) => Promise<[unknown, unknown]>
            >(),
            commit: jest.fn<() => Promise<void>>().mockResolvedValue(),
            rollback: jest.fn<() => Promise<void>>().mockResolvedValue(),
            release: jest.fn<() => void>(),
        };

        mockPool = {
            getConnection: jest.fn<() => Promise<MockConnection>>()
                .mockResolvedValue(mockConnection),
        };

        repository = new EvaluationResultRepository(
            mockPool as unknown as Pool,
        );
    });

    describe('complete', () => {
        const result = {
            evaluationId: 'evaluation-123',
            pymeId: 'pyme-456',
            domain: 'example.com',
            score: 85,
            level: 'Bajo',

            layersSummary: {
                dns: {
                    status: 'completed',
                    findings: 0,
                },
                tls: {
                    status: 'completed',
                    findings: 0,
                },
                headers: {
                    status: 'completed',
                    findings: 1,
                },
            },
        
            findings: [
                {
                    layer: 'headers',
                    severity: 'low',
                    title: 'Cabecera de seguridad ausente',
                    description: 'No se encontró una cabecera de seguridad esperada.',
                    evidence: null,
                },
            ],
        };

        it('guarda el resultado y confirma la transacción', async () => {
            mockConnection.execute.mockResolvedValue([
                { affectedRows: 1 },
                [],
            ]);
        
            // Ejecutar primero la operación que estamos probando.
            await repository.complete(result);
        
            expect(mockConnection.beginTransaction).toHaveBeenCalledTimes(1);
            expect(mockConnection.execute).toHaveBeenCalledTimes(3);
        
            // 1. Actualización de evaluaciones.
            const firstCall = mockConnection.execute.mock.calls[0];
        
            expect(firstCall).toBeDefined();
        
            const [sql, values] = firstCall!;
        
            expect(sql).toContain("SET estado = 'done'");
            expect(sql).toContain('score = ?');
            expect(sql).toContain('nivel = ?');
            expect(sql).toContain('capas_resumen = ?');
            expect(sql).toContain('finalizado_en');
        
            expect(values).toEqual([
                85,
                'Bajo',
                JSON.stringify(result.layersSummary),
                'evaluation-123',
            ]);
        
            // 2. Inserción de hallazgos.
            const findingCall = mockConnection.execute.mock.calls[1];
        
            expect(findingCall).toBeDefined();
        
            const [findingSql, findingValues] = findingCall!;
        
            expect(findingSql).toContain('INSERT INTO hallazgos');
        
            expect(findingValues).toEqual([
                expect.any(String),
                'evaluation-123',
                'headers',
                'BAJA',
                'Cabecera de seguridad ausente',
                'No se encontró una cabecera de seguridad esperada.',
                null,
            ]);
        
            // 3. Inserción del historial.
            const historyCall = mockConnection.execute.mock.calls[2];
        
            expect(historyCall).toBeDefined();
        
            const [historySql, historyValues] = historyCall!;
        
            expect(historySql).toContain('INSERT INTO historial_scores');
        
            expect(historyValues).toEqual([
                expect.any(String),
                'example.com',
                'pyme-456',
                85,
            ]);
        
            expect(mockConnection.commit).toHaveBeenCalledTimes(1);
            expect(mockConnection.rollback).not.toHaveBeenCalled();
            expect(mockConnection.release).toHaveBeenCalledTimes(1);
        });

        it('guarda varios hallazgos con una sola consulta', async () => {
            const additionalFinding = {
                layer: 'tls',
                severity: 'medium',
                title: 'Certificado por vencer',
                description: 'El certificado TLS está próximo a vencer.',
                evidence: null,
            };
            mockConnection.execute
                .mockResolvedValueOnce([{ affectedRows: 1 }, []])
                .mockResolvedValueOnce([{ affectedRows: 2 }, []])
                .mockResolvedValueOnce([{ affectedRows: 1 }, []]);

            await repository.complete({
                ...result,
                findings: [result.findings[0]!, additionalFinding],
            });

            expect(mockConnection.execute).toHaveBeenCalledTimes(3);
            const findingCall = mockConnection.execute.mock.calls[1];
            expect(findingCall).toBeDefined();

            const [findingSql, findingValues] = findingCall!;
            expect(findingSql).toContain('VALUES (?, ?, ?, ?, ?, ?, ?), (?, ?, ?, ?, ?, ?, ?)');
            expect(findingValues).toHaveLength(14);
        });

        it('revierte si la inserción no guarda todos los hallazgos', async () => {
            mockConnection.execute
                .mockResolvedValueOnce([{ affectedRows: 1 }, []])
                .mockResolvedValueOnce([{ affectedRows: 0 }, []]);

            await expect(repository.complete(result)).rejects.toThrow(
                'No fue posible guardar todos los hallazgos.',
            );

            expect(mockConnection.rollback).toHaveBeenCalledTimes(1);
            expect(mockConnection.commit).not.toHaveBeenCalled();
            expect(mockConnection.release).toHaveBeenCalledTimes(1);
        });

        it('rechaza puntuaciones fuera del intervalo permitido', async () => {
            await expect(
                repository.complete({ ...result, score: 101 }),
            ).rejects.toThrow();

            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it('rechaza puntuaciones negativas', async () => {
            await expect(
                repository.complete({ ...result, score: -1 }),
            ).rejects.toThrow();

            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it('rechaza puntuaciones no enteras', async () => {
            await expect(
                repository.complete({ ...result, score: 85.5 }),
            ).rejects.toThrow();

            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it('rechaza niveles vacíos', async () => {
            await expect(
                repository.complete({ ...result, level: ' ' }),
            ).rejects.toThrow();

            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it('rechaza identificadores vacíos', async () => {
            await expect(
                repository.complete({ ...result, evaluationId: ' ' }),
            ).rejects.toThrow();

            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it('revierte la transacción si falla la actualización', async () => {
            mockConnection.execute.mockRejectedValue(
                new Error('Error de actualización'),
            );

            await expect(repository.complete(result)).rejects.toThrow(
                'Error de actualización',
            );

            expect(mockConnection.rollback).toHaveBeenCalledTimes(1);
            expect(mockConnection.commit).not.toHaveBeenCalled();
            expect(mockConnection.release).toHaveBeenCalledTimes(1);
        });

        it('rechaza completar una evaluación que no está en estado running', async () => {
            mockConnection.execute.mockResolvedValue([
                { affectedRows: 0 },
                [],
            ]);

            await expect(repository.complete(result)).rejects.toThrow();

            expect(mockConnection.rollback).toHaveBeenCalledTimes(1);
            expect(mockConnection.commit).not.toHaveBeenCalled();
            expect(mockConnection.release).toHaveBeenCalledTimes(1);
        });

        it('libera la conexión si falla el inicio de la transacción', async () => {
            mockConnection.beginTransaction.mockRejectedValue(
                new Error('Error al iniciar la transacción'),
            );

            await expect(repository.complete(result)).rejects.toThrow(
                'Error al iniciar la transacción',
            );

            expect(mockConnection.rollback).not.toHaveBeenCalled();
            expect(mockConnection.release).toHaveBeenCalledTimes(1);
        });

        it('propaga el error si no puede obtener una conexión', async () => {
            mockPool.getConnection.mockRejectedValue(
                new Error('Sin conexiones disponibles'),
            );

            await expect(repository.complete(result)).rejects.toThrow(
                'Sin conexiones disponibles',
            );
        });

        it('conserva el error original si también falla el rollback', async () => {
            mockConnection.execute.mockRejectedValue(
                new Error('Error original'),
            );
            mockConnection.rollback.mockRejectedValue(
                new Error('Error de rollback'),
            );

            await expect(repository.complete(result)).rejects.toThrow(
                'Error original',
            );

            expect(mockConnection.release).toHaveBeenCalledTimes(1);
        });

        it('rechaza un resultado nulo', async () => {
            await expect(
                repository.complete(null as never),
            ).rejects.toThrow(
                'El resultado de la evaluación es obligatorio.',
            );
        
            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it('rechaza un resultado que no sea un objeto', async () => {
            await expect(
                repository.complete(123 as never),
            ).rejects.toThrow(
                'El resultado de la evaluación es obligatorio.',
            );
        
            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it('rechaza dominios que superan los 255 caracteres', async () => {
            await expect(
                repository.complete({
                    ...result,
                    domain: 'a'.repeat(256),
                }),
            ).rejects.toThrow(
                'El dominio supera los 255 caracteres.',
            );
        
            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it.each([
            ['nulo', null],
            ['un valor primitivo', 'invalid'],
            ['un array', []],
        ])(
            'rechaza un resumen de capas que sea %s',
            async (_description, invalidSummary) => {
                await expect(
                    repository.complete({
                        ...result,
                        layersSummary: invalidSummary as never,
                    }),
                ).rejects.toThrow(
                    'El resumen de las capas debe ser un objeto válido.',
                );
            
                expect(mockPool.getConnection).not.toHaveBeenCalled();
            },
        );

        it('rechaza hallazgos que no sean una lista', async () => {
            await expect(
                repository.complete({
                    ...result,
                    findings: null as never,
                }),
            ).rejects.toThrow(TypeError);
        
            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it('rechaza un hallazgo nulo', async () => {
            await expect(
                repository.complete({
                    ...result,
                    findings: [null as never],
                }),
            ).rejects.toThrow(
                'El hallazgo proporcionado no es válido.',
            );
        
            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it('rechaza capas de hallazgos que superan los 50 caracteres', async () => {
            await expect(
                repository.complete({
                    ...result,
                    findings: [{
                        ...result.findings[0]!,
                        layer: 'a'.repeat(51),
                    }],
                }),
            ).rejects.toThrow(
                'La capa supera los 50 caracteres.',
            );
        
            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it('rechaza títulos de hallazgos que superan los 255 caracteres', async () => {
            await expect(
                repository.complete({
                    ...result,
                    findings: [{
                        ...result.findings[0]!,
                        title: 'a'.repeat(256),
                    }],
                }),
            ).rejects.toThrow(
                'El título supera los 255 caracteres.',
            );
        
            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it('rechaza evidencias que no sean texto ni null', async () => {
            await expect(
                repository.complete({
                    ...result,
                    findings: [{
                        ...result.findings[0]!,
                        evidence: {} as never,
                    }],
                }),
            ).rejects.toThrow(
                'La evidencia del hallazgo debe ser texto o null.',
            );
        
            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it('rechaza hallazgos sin severidad', async () => {
            await expect(
                repository.complete({
                    ...result,
                    findings: [{
                        ...result.findings[0]!,
                        severity: '',
                    }],
                }),
            ).rejects.toThrow(
                'La severidad del hallazgo es obligatoria.',
            );
        
            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it('rechaza severidades que no están permitidas', async () => {
            await expect(
                repository.complete({
                    ...result,
                    findings: [{
                        ...result.findings[0]!,
                        severity: 'informational',
                    }],
                }),
            ).rejects.toThrow(
                "La severidad 'informational' no está permitida.",
            );
        
            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

    });

    describe('fail', () => {
        it('marca como fallida una evaluación en ejecución', async () => {
            mockConnection.execute.mockResolvedValue([
                { affectedRows: 1 },
                [],
            ]);

            await repository.fail('evaluation-123');

            expect(mockConnection.execute).toHaveBeenCalledWith(
                expect.stringContaining("SET estado = 'failed'"),
                ['evaluation-123'],
            );

            expect(mockConnection.commit).toHaveBeenCalledTimes(1);
            expect(mockConnection.release).toHaveBeenCalledTimes(1);
        });

        it('rechaza marcar como fallida una evaluación que no está en ejecución', async () => {
            mockConnection.execute.mockResolvedValue([
                { affectedRows: 0 },
                [],
            ]);

            await expect(
                repository.fail('evaluation-123'),
            ).rejects.toThrow();

            expect(mockConnection.rollback).toHaveBeenCalledTimes(1);
            expect(mockConnection.release).toHaveBeenCalledTimes(1);
        });

        it('rechaza identificadores vacíos al marcar una evaluación fallida', async () => {
            await expect(repository.fail(' ')).rejects.toThrow();

            expect(mockPool.getConnection).not.toHaveBeenCalled();
        });

        it('revierte la transacción si falla la actualización del estado fallido', async () => {
            mockConnection.execute.mockRejectedValue(
                new Error('Error de actualización'),
            );

            await expect(
                repository.fail('evaluation-123'),
            ).rejects.toThrow('Error de actualización');

            expect(mockConnection.rollback).toHaveBeenCalledTimes(1);
            expect(mockConnection.release).toHaveBeenCalledTimes(1);
        });

        it('libera la conexión si falla el inicio de la transacción', async () => {
            mockConnection.beginTransaction.mockRejectedValue(
                new Error('Error al iniciar la transacción'),
            );

            await expect(
                repository.fail('evaluation-123'),
            ).rejects.toThrow('Error al iniciar la transacción');

            expect(mockConnection.rollback).not.toHaveBeenCalled();
            expect(mockConnection.release).toHaveBeenCalledTimes(1);
        });
    });

});

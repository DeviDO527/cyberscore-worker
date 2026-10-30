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
            score: 85,
            level: 'Bajo',
            layersSummary: {
                tls: { status: 'completed', findings: 0 },
                headers: { status: 'completed', findings: 2 },
            },
        };

        it('guarda el resultado y confirma la transacción', async () => {
            mockConnection.execute.mockResolvedValue([
                { affectedRows: 1 },
                [],
            ]);

            await repository.complete(result);

            expect(mockConnection.beginTransaction).toHaveBeenCalledTimes(1);
            expect(mockConnection.execute).toHaveBeenCalledTimes(1);

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

            expect(mockConnection.commit).toHaveBeenCalledTimes(1);
            expect(mockConnection.rollback).not.toHaveBeenCalled();
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

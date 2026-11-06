import { describe, it, expect, jest, beforeEach } from '@jest/globals';
import type { Pool } from 'mysql2/promise';
import { EvaluationRepository } from '../src/jobs/evaluation.repository';

describe('EvaluationRepository', () => {
    type MockConnection = {
      beginTransaction: jest.Mock<() => Promise<void>>;
      query: jest.Mock<
        (sql: string) => Promise<[unknown[], unknown]>
      >;
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

    let repository: EvaluationRepository;
    let mockConnection: MockConnection;
    let mockPool: MockPool;

    beforeEach(() => {
      mockConnection = {
        beginTransaction: jest.fn<() => Promise<void>>().mockResolvedValue(),
        query: jest.fn<
          (sql: string) => Promise<[unknown[], unknown]>
        >(),
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

      repository = new EvaluationRepository(
        mockPool as unknown as Pool,
      );
    });
    it('reclama una evaluación pendiente y devuelve sus datos', async () => {
        mockConnection.query.mockResolvedValue([
            [
                {
                    id: 'evaluation-123',
                    pyme_id: 'pyme-456',
                    dominio: 'example.com',
                    ingresos_mensuales: '30000000.00',
                    horas_operativas: 300,
                    moneda: 'COP',
                },
            ],
            [],
        ]);

        mockConnection.execute.mockResolvedValue([
          { affectedRows: 1 },
          [],
        ]);

        const result = await repository.claimNext();
        const queryCall = mockConnection.query.mock.calls[0];

        expect(queryCall).toBeDefined();
            
        const [sql] = queryCall!;
            
        expect(sql).toContain('INNER JOIN pymes');
        expect(sql).toContain('ingresos_mensuales');
        expect(sql).toContain('horas_operativas');
        expect(sql).toContain('moneda');
        expect(queryCall).toBeDefined();
        expect(sql).toContain("WHERE e.estado = 'queued'");
        expect(sql).toContain('ORDER BY e.iniciado_en ASC, e.id ASC');
        expect(sql).toContain('LIMIT 1');
        expect(sql).toContain('FOR UPDATE');

        expect(result).toEqual({
            id: 'evaluation-123',
            pymeId: 'pyme-456',
            domain: 'example.com',
            monthlyRevenue: 30000000,
            operatingHours: 300,
            currency: 'COP',
        });

        expect(mockConnection.beginTransaction).toHaveBeenCalledTimes(1);
        expect(mockConnection.execute).toHaveBeenCalledWith(
          expect.stringContaining("SET estado = 'running'"),
          ['evaluation-123'],
        );
        expect(mockConnection.commit).toHaveBeenCalledTimes(1);
        expect(mockConnection.release).toHaveBeenCalledTimes(1);

    });

    it('devuelve null cuando no existen evaluaciones pendientes', async () => {
        mockConnection.query.mockResolvedValue([[], []]);
        
        const result = await repository.claimNext();
        
        expect(result).toBeNull();
        expect(mockConnection.execute).not.toHaveBeenCalled();
        expect(mockConnection.commit).toHaveBeenCalledTimes(1);
        expect(mockConnection.release).toHaveBeenCalledTimes(1);

    });

    it('revierte la transacción si falla la actualización', async () => {
        mockConnection.query.mockResolvedValue([
            [
                {
                    id: 'evaluation-123',
                    pyme_id: 'pyme-456',
                    dominio: 'example.com',
                    ingresos_mensuales: '30000000.00',
                    horas_operativas: 300,
                    moneda: 'COP',
                },
            ],
            [],
        ]);

        mockConnection.execute.mockRejectedValue(
          new Error('Error de actualización'),
        );

        await expect(repository.claimNext()).rejects.toThrow(
          'Error de actualización',
        );

        expect(mockConnection.rollback).toHaveBeenCalledTimes(1);
        expect(mockConnection.release).toHaveBeenCalledTimes(1);

    });

    it('revierte la transacción si falla la consulta de evaluaciones', async () => {
        mockConnection.query.mockRejectedValue(
            new Error('Error de consulta'),
        );

        await expect(repository.claimNext()).rejects.toThrow(
            'Error de consulta',
        );

        expect(mockConnection.rollback).toHaveBeenCalledTimes(1);
        expect(mockConnection.release).toHaveBeenCalledTimes(1);
        expect(mockConnection.commit).not.toHaveBeenCalled();
    });

    it('revierte la transacción si la actualización no afecta ninguna fila', async () => {
        mockConnection.query.mockResolvedValue([
            [
                {
                    id: 'evaluation-123',
                    pyme_id: 'pyme-456',
                    dominio: 'example.com',
                    ingresos_mensuales: '30000000.00',
                    horas_operativas: 300,
                    moneda: 'COP',
                },
            ],
            [],
        ]);

        mockConnection.execute.mockResolvedValue([
            { affectedRows: 0 },
            [],
        ]);

        await expect(repository.claimNext()).rejects.toThrow(
            'No fue posible reclamar la evaluación evaluation-123.',
        );

        expect(mockConnection.rollback).toHaveBeenCalledTimes(1);
        expect(mockConnection.commit).not.toHaveBeenCalled();
        expect(mockConnection.release).toHaveBeenCalledTimes(1);
    });

    it('libera la conexión si falla el inicio de la transacción', async () => {
        mockConnection.beginTransaction.mockRejectedValue(
            new Error('Error al iniciar transacción'),
        );

        await expect(repository.claimNext()).rejects.toThrow(
            'Error al iniciar transacción',
        );

        expect(mockConnection.rollback).not.toHaveBeenCalled();
        expect(mockConnection.release).toHaveBeenCalledTimes(1);
    });

    it('propaga el error si no puede adquirir una conexión', async () => {
        mockPool.getConnection.mockRejectedValue(
            new Error('MySQL no disponible'),
        );

        await expect(repository.claimNext()).rejects.toThrow(
            'MySQL no disponible',
        );

        expect(mockConnection.beginTransaction).not.toHaveBeenCalled();
        expect(mockConnection.release).not.toHaveBeenCalled();
    });

    it('conserva el error original si también falla el rollback', async () => {
        mockConnection.query.mockRejectedValue(
            new Error('Error de consulta original'),
        );

        mockConnection.rollback.mockRejectedValue(
            new Error('Error durante rollback'),
        );

        await expect(repository.claimNext()).rejects.toThrow(
            'Error de consulta original',
        );

        expect(mockConnection.rollback).toHaveBeenCalledTimes(1);
        expect(mockConnection.release).toHaveBeenCalledTimes(1);
    });

    it('propaga el error si falla el commit y libera la conexión', async () => {
        mockConnection.query.mockResolvedValue([
            [
                {
                    id: 'evaluation-123',
                    pyme_id: 'pyme-456',
                    dominio: 'example.com',
                    ingresos_mensuales: '30000000.00',
                    horas_operativas: 300,
                    moneda: 'COP',
                },
            ],
            [],
        ]);
    
        mockConnection.execute.mockResolvedValue([
            { affectedRows: 1 },
            [],
        ]);
    
        mockConnection.commit.mockRejectedValue(
            new Error('Error al confirmar transacción'),
        );
    
        await expect(repository.claimNext()).rejects.toThrow(
            'Error al confirmar transacción',
        );
    
        expect(mockConnection.commit).toHaveBeenCalledTimes(1);
        expect(mockConnection.release).toHaveBeenCalledTimes(1);
    });

    it('rechaza una PYME con ingresos mensuales inválidos', async () => {
        mockConnection.query.mockResolvedValue([
            [
                {
                    id: 'evaluation-123',
                    pyme_id: 'pyme-456',
                    dominio: 'example.com',
                    ingresos_mensuales: 'invalid',
                    horas_operativas: 300,
                    moneda: 'COP',
                },
            ],
            [],
        ]);

        await expect(
            repository.claimNext(),
        ).rejects.toThrow();

        expect(mockConnection.execute).not.toHaveBeenCalled();
        expect(mockConnection.rollback).toHaveBeenCalledTimes(1);
        expect(mockConnection.release).toHaveBeenCalledTimes(1);
    });

    describe('Validación de horas operativas', () => {

        it.each([
            {
                description: 'horas fraccionarias',
                hours: 7.5,
            },
            {
                description: 'horas menores que 1',
                hours: 0,
            },
            {
                description: 'horas superiores a 744',
                hours: 745,
            },
        ])(
            'rechaza $description',
            async ({ hours }) => {

                mockConnection.query.mockResolvedValue([
                    [
                        {
                            id: 'evaluation-123',
                            pyme_id: 'pyme-456',
                            dominio: 'example.com',
                            ingresos_mensuales: '30000000.00',
                            horas_operativas: hours,
                            moneda: 'COP',
                        },
                    ],
                    [],
                ]);

                await expect(
                    repository.claimNext(),
                ).rejects.toThrow(
                    'Las horas operativas de la PYME pyme-456 no son válidas.',
                );

                expect(mockConnection.execute).not.toHaveBeenCalled();
                expect(mockConnection.rollback).toHaveBeenCalledTimes(1);
                expect(mockConnection.release).toHaveBeenCalledTimes(1);
            },
        );
    });

    describe('Validación de moneda', () => {

        it('rechaza una moneda nula', async () => {

            mockConnection.query.mockResolvedValue([
                [
                    {
                        id: 'evaluation-123',
                        pyme_id: 'pyme-456',
                        dominio: 'example.com',
                        ingresos_mensuales: '30000000.00',
                        horas_operativas: 300,
                        moneda: null,
                    },
                ],
                [],
            ]);

            await expect(
                repository.claimNext(),
            ).rejects.toThrow(
                'La moneda de la PYME pyme-456 no es válida.',
            );

            expect(mockConnection.execute).not.toHaveBeenCalled();
            expect(mockConnection.rollback).toHaveBeenCalledTimes(1);
            expect(mockConnection.release).toHaveBeenCalledTimes(1);
        });

        it('rechaza monedas no soportadas', async () => {

            mockConnection.query.mockResolvedValue([
                [
                    {
                        id: 'evaluation-123',
                        pyme_id: 'pyme-456',
                        dominio: 'example.com',
                        ingresos_mensuales: '30000000.00',
                        horas_operativas: 300,
                        moneda: 'GBP',
                    },
                ],
                [],
            ]);

            await expect(
                repository.claimNext(),
            ).rejects.toThrow(
                'La moneda de la PYME pyme-456 no es válida.',
            );

            expect(mockConnection.execute).not.toHaveBeenCalled();
            expect(mockConnection.rollback).toHaveBeenCalledTimes(1);
            expect(mockConnection.release).toHaveBeenCalledTimes(1);
        });
    });

});

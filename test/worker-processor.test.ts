import { beforeEach, describe, expect, it, jest } from '@jest/globals';

import { WorkerProcessor } from '../src/jobs/worker-processor';

describe('WorkerProcessor', () => {
    const evaluation = {
        id: 'evaluation-123',
        pymeId: 'pyme-456',
        domain: 'example.com',
    };

    const analysisResult = {
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

    let evaluationRepository: {
        claimNext: ReturnType<typeof jest.fn>;
    };

    let resultRepository: {
        complete: ReturnType<typeof jest.fn>;
        fail: ReturnType<typeof jest.fn>;
    };

    let analyzeEvaluation: ReturnType<typeof jest.fn>;

    let logger: {
        info: ReturnType<typeof jest.fn>;
        warn: ReturnType<typeof jest.fn>;
        error: ReturnType<typeof jest.fn>;
    };

    let processor: WorkerProcessor;

    beforeEach(() => {
        jest.clearAllMocks();

        evaluationRepository = {
            claimNext: jest.fn(),
        };

        resultRepository = {
            complete: jest.fn(),
            fail: jest.fn(),
        };

        analyzeEvaluation = jest.fn();

        logger = {
            info: jest.fn(),
            warn: jest.fn(),
            error: jest.fn(),
        };

        processor = new WorkerProcessor(
            evaluationRepository as never,
            resultRepository as never,
            analyzeEvaluation as never,
            logger as never,
        );
    });

    it('devuelve false cuando no existen evaluaciones pendientes', async () => {
        evaluationRepository.claimNext.mockResolvedValue(null);

        const result = await processor.processNext();

        expect(result).toBe(false);

        expect(analyzeEvaluation).not.toHaveBeenCalled();
        expect(resultRepository.complete).not.toHaveBeenCalled();
        expect(resultRepository.fail).not.toHaveBeenCalled();
    });

    it('reclama una evaluación y ejecuta el análisis', async () => {
        evaluationRepository.claimNext.mockResolvedValue(evaluation);
        analyzeEvaluation.mockResolvedValue(analysisResult);
        resultRepository.complete.mockResolvedValue(undefined);

        await processor.processNext();

        expect(evaluationRepository.claimNext).toHaveBeenCalledTimes(1);

        expect(analyzeEvaluation).toHaveBeenCalledWith(evaluation);
    });

    it('guarda el resultado obtenido durante el análisis', async () => {
        evaluationRepository.claimNext.mockResolvedValue(evaluation);
        analyzeEvaluation.mockResolvedValue(analysisResult);
        resultRepository.complete.mockResolvedValue(undefined);

        await processor.processNext();

        expect(resultRepository.complete).toHaveBeenCalledWith({
            evaluationId: evaluation.id,
            pymeId: evaluation.pymeId,
            domain: evaluation.domain,
            score: analysisResult.score,
            level: analysisResult.level,
            layersSummary: analysisResult.layersSummary,
            findings: analysisResult.findings,
        });
    });

    it('devuelve true cuando procesa una evaluación correctamente', async () => {
        evaluationRepository.claimNext.mockResolvedValue(evaluation);
        analyzeEvaluation.mockResolvedValue(analysisResult);
        resultRepository.complete.mockResolvedValue(undefined);

        const result = await processor.processNext();

        expect(result).toBe(true);
    });

    it('no marca como fallida una evaluación procesada correctamente', async () => {
        evaluationRepository.claimNext.mockResolvedValue(evaluation);
        analyzeEvaluation.mockResolvedValue(analysisResult);
        resultRepository.complete.mockResolvedValue(undefined);

        await processor.processNext();

        expect(resultRepository.fail).not.toHaveBeenCalled();
    });

    it('marca como fallida la evaluación cuando el análisis produce un error', async () => {
        evaluationRepository.claimNext.mockResolvedValue(evaluation);

        analyzeEvaluation.mockRejectedValue(
            new Error('Error durante el análisis'),
        );

        resultRepository.fail.mockResolvedValue(undefined);

        await processor.processNext();

        expect(resultRepository.fail).toHaveBeenCalledWith(
            evaluation.id,
        );
    });

    it('no guarda el resultado cuando falla el análisis', async () => {
        evaluationRepository.claimNext.mockResolvedValue(evaluation);

        analyzeEvaluation.mockRejectedValue(
            new Error('Error durante el análisis'),
        );

        resultRepository.fail.mockResolvedValue(undefined);

        await processor.processNext();

        expect(resultRepository.complete).not.toHaveBeenCalled();
    });

    it('registra el error cuando falla el análisis', async () => {
        evaluationRepository.claimNext.mockResolvedValue(evaluation);

        analyzeEvaluation.mockRejectedValue(
            new Error('Error durante el análisis'),
        );

        resultRepository.fail.mockResolvedValue(undefined);

        await processor.processNext();

        expect(logger.error).toHaveBeenCalled();
    });

    it('maneja el error si no puede marcar como fallida una evaluación', async () => {
        evaluationRepository.claimNext.mockResolvedValue(evaluation);

        analyzeEvaluation.mockRejectedValue(
            new Error('Error durante el análisis'),
        );

        resultRepository.fail.mockRejectedValue(
            new Error('No se pudo actualizar el estado'),
        );

        await expect(
            processor.processNext(),
        ).resolves.toBe(true);

        expect(logger.error).toHaveBeenCalled();
    });

    it('propaga el error si no puede reclamar una evaluación', async () => {
        evaluationRepository.claimNext.mockRejectedValue(
            new Error('MySQL no disponible'),
        );

        await expect(
            processor.processNext(),
        ).rejects.toThrow('MySQL no disponible');

        expect(analyzeEvaluation).not.toHaveBeenCalled();
        expect(resultRepository.complete).not.toHaveBeenCalled();
        expect(resultRepository.fail).not.toHaveBeenCalled();
    });

    it('registra un mensaje alternativo cuando el análisis falla con un valor que no es Error', async () => {
        evaluationRepository.claimNext.mockResolvedValue(evaluation);
    
        analyzeEvaluation.mockRejectedValue('Error desconocido');
    
        resultRepository.fail.mockResolvedValue(undefined);
    
        await processor.processNext();
    
        expect(logger.error).toHaveBeenCalledWith(
            expect.objectContaining({
                evaluationId: evaluation.id,
                error: 'Error desconocido durante el procesamiento.',
            }),
            'Falló el procesamiento de la evaluación.',
        );
    });
    
    it('registra un mensaje alternativo cuando falla el registro con un valor que no es Error', async () => {
        evaluationRepository.claimNext.mockResolvedValue(evaluation);
    
        analyzeEvaluation.mockRejectedValue(
            new Error('Error durante el análisis'),
        );
    
        resultRepository.fail.mockRejectedValue('Fallo desconocido');
    
        await processor.processNext();
    
        expect(logger.error).toHaveBeenCalledWith(
            expect.objectContaining({
                evaluationId: evaluation.id,
                error: 'Error desconocido al marcar la evaluación como fallida.',
            }),
            'No fue posible registrar el fallo de la evaluación.',
        );
    });


});
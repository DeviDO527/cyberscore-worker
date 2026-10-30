import type { EvaluationRepository } from './evaluation.repository';
import type { EvaluationResultRepository } from './evaluation-result.repository';

interface Evaluation {
    id: string;
    pymeId: string;
    domain: string;
}

interface AnalysisResult {
    score: number;
    level: string;
    layersSummary: Record<string, unknown>;
}

interface ResultData {
    evaluationId: string;
    score: number;
    level: string;
    layersSummary: Record<string, unknown>;
}

interface ProcessorLogger {
    info: (...args: any[]) => void;
    warn: (...args: any[]) => void;
    error: (...args: any[]) => void;
}

type EvaluationAnalyzer = (
    evaluation: Evaluation,
) => Promise<AnalysisResult>;

export class WorkerProcessor {
    constructor(
    private readonly evaluationRepository: EvaluationRepository,
    private readonly resultRepository: EvaluationResultRepository,
    private readonly analyzeEvaluation: EvaluationAnalyzer,
    private readonly logger: ProcessorLogger,
    ) {}
    
    async processNext(): Promise<boolean> {
        const evaluation = await this.evaluationRepository.claimNext();
    
        if (!evaluation) {
            return false;
        }
    
        try {
            const analysis = await this.analyzeEvaluation(
                evaluation as Evaluation,
            );
        
            const result: ResultData = {
                evaluationId: evaluation.id,
                score: analysis.score,
                level: analysis.level,
                layersSummary: analysis.layersSummary,
            };
        
            await this.resultRepository.complete(result);
        
            this.logger.info(
                { evaluationId: evaluation.id },
                'Evaluación procesada correctamente.',
            );
        
            return true;
        } catch (error: unknown) {
            this.logger.error(
                {
                    evaluationId: evaluation.id,
                    error:
                        error instanceof Error
                            ? error.message
                            : 'Error desconocido durante el procesamiento.',
                },
                'Falló el procesamiento de la evaluación.',
            );
        
            try {
                await this.resultRepository.fail(evaluation.id);
            } catch (failureError: unknown) {
                this.logger.error(
                    {
                        evaluationId: evaluation.id,
                        error:
                            failureError instanceof Error
                                ? failureError.message
                                : 'Error desconocido al marcar la evaluación como fallida.',
                    },
                    'No fue posible registrar el fallo de la evaluación.',
                );
            }
        
            return true;
        }
    }

}

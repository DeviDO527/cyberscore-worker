import type {
    EvaluationResult,
    FindingToPersist,
} from './evaluation-result.repository';

import type { PendingEvaluation } from './evaluation.repository';

interface AnalysisResult {
    score: number;
    level: string;
    layersSummary: Record<string, unknown>;
    findings: FindingToPersist[];
}

interface ProcessorLogger {
    info: (...args: any[]) => void;
    warn: (...args: any[]) => void;
    error: (...args: any[]) => void;
}

type EvaluationAnalyzer = (
    evaluation: PendingEvaluation,
) => Promise<AnalysisResult>;

export class WorkerProcessor {
    constructor(
        private readonly evaluationRepository: {
            claimNext(): Promise<PendingEvaluation | null>;
        },
        private readonly resultRepository: {
            complete(result: EvaluationResult): Promise<void>;
            fail(evaluationId: string): Promise<void>;
        },
        private readonly analyzeEvaluation: EvaluationAnalyzer,
        private readonly logger: ProcessorLogger,
    ) {}

    async processNext(): Promise<boolean> {
        const evaluation = await this.evaluationRepository.claimNext();

        if (!evaluation) {
            return false;
        }

        try {
            const analysis = await this.analyzeEvaluation(evaluation);

            const result: EvaluationResult = {
                evaluationId: evaluation.id,
                pymeId: evaluation.pymeId,
                domain: evaluation.domain,
                score: analysis.score,
                level: analysis.level,
                layersSummary: analysis.layersSummary,
                findings: analysis.findings,
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

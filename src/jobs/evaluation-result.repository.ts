import type { Pool, PoolConnection, ResultSetHeader,} from 'mysql2/promise';

export interface EvaluationResult {
    evaluationId: string;
    score: number;
    level: string;
    layersSummary: Record<string, unknown>;
}

export class EvaluationResultRepository {
    constructor(private readonly pool: Pool) {}

    async complete(result: EvaluationResult): Promise<void> {
        this.validateEvaluationId(result.evaluationId);
        this.validateScore(result.score);
        this.validateLevel(result.level);

        if (
            result.layersSummary === null ||
            typeof result.layersSummary !== 'object' ||
            Array.isArray(result.layersSummary)
        ) {
            throw new Error(
                'El resumen de las capas debe ser un objeto válido.',
            );
        }

        const connection = await this.pool.getConnection();
        let transactionStarted = false;

        try {
            await connection.beginTransaction();
            transactionStarted = true;

            const [updateResult] = await connection.execute<ResultSetHeader>(
                `UPDATE evaluaciones
                 SET estado = 'done',
                     score = ?,
                     nivel = ?,
                     capas_resumen = ?,
                     finalizado_en = CURRENT_TIMESTAMP
                 WHERE id = ?
                   AND estado = 'running'`,
                [
                    result.score,
                    result.level.trim(),
                    JSON.stringify(result.layersSummary),
                    result.evaluationId.trim(),
                ],
            );

            this.ensureOneRowUpdated(
                updateResult,
                'No fue posible completar la evaluación.',
            );

            await connection.commit();
            transactionStarted = false;
        } catch (error) {
            if (transactionStarted) {
                await this.rollbackPreservingOriginalError(
                    connection,
                    error,
                );
            }

            throw error;
        } finally {
            connection.release();
        }
    }

    async fail(evaluationId: string): Promise<void> {
        this.validateEvaluationId(evaluationId);

        const connection = await this.pool.getConnection();
        let transactionStarted = false;

        try {
            await connection.beginTransaction();
            transactionStarted = true;

            const [updateResult] = await connection.execute<ResultSetHeader>(
                `UPDATE evaluaciones
                 SET estado = 'failed',
                     finalizado_en = CURRENT_TIMESTAMP
                 WHERE id = ?
                   AND estado = 'running'`,
                [evaluationId.trim()],
            );

            this.ensureOneRowUpdated(
                updateResult,
                'No fue posible marcar la evaluación como fallida.',
            );

            await connection.commit();
            transactionStarted = false;
        } catch (error) {
            if (transactionStarted) {
                await this.rollbackPreservingOriginalError(
                    connection,
                    error,
                );
            }

            throw error;
        } finally {
            connection.release();
        }
    }

    private validateEvaluationId(evaluationId: string): void {
        if (
            typeof evaluationId !== 'string' ||
            evaluationId.trim().length === 0
        ) {
            throw new Error(
                'El identificador de la evaluación es obligatorio.',
            );
        }
    }

    private validateScore(score: number): void {
        if (
            !Number.isInteger(score) ||
            score < 0 ||
            score > 100
        ) {
            throw new Error(
                'La puntuación debe ser un número entero entre 0 y 100.',
            );
        }
    }

    private validateLevel(level: string): void {
        if (
            typeof level !== 'string' ||
            level.trim().length === 0
        ) {
            throw new Error(
                'El nivel de riesgo es obligatorio.',
            );
        }
    }

    private ensureOneRowUpdated(
        result: ResultSetHeader,
        message: string,
    ): void {
        if (result.affectedRows !== 1) {
            throw new Error(message);
        }
    }

    private async rollbackPreservingOriginalError(
        connection: PoolConnection,
        originalError: unknown,
    ): Promise<void> {
        try {
            await connection.rollback();
        } catch {
            // Conservamos el error original de la operación.
        }

        // El error original se propaga desde el bloque catch.
        void originalError;
    }

}

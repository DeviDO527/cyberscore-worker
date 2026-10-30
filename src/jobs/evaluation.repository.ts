import type { Pool, RowDataPacket, ResultSetHeader } from 'mysql2/promise';

export interface PendingEvaluation {
    id: string;
    pymeId: string;
    domain: string;
}

interface EvaluationRow extends RowDataPacket {
    id: string;
    pyme_id: string;
    dominio: string;
}

export class EvaluationRepository {
    constructor(private readonly pool: Pool) {}

    async claimNext(): Promise<PendingEvaluation | null> {
        const connection = await this.pool.getConnection();

        let transactionStarted = false;

        try {
            await connection.beginTransaction();
            transactionStarted = true;

            const [rows] = await connection.query<EvaluationRow[]>(
                `SELECT id, pyme_id, dominio
                 FROM evaluaciones
                 WHERE estado = 'queued'
                 ORDER BY iniciado_en ASC, id ASC
                 LIMIT 1
                 FOR UPDATE`,
            );

            const evaluation = rows[0];

            if (!evaluation) {
                await connection.commit();
                transactionStarted = false;
                return null;
            }

            const [updateResult] = await connection.execute<ResultSetHeader>(
                `UPDATE evaluaciones
                 SET estado = 'running'
                 WHERE id = ?
                   AND estado = 'queued'`,
                [evaluation.id],
            );

            if (updateResult.affectedRows !== 1) {
                throw new Error(
                    `No fue posible reclamar la evaluación ${evaluation.id}.`,
                );
            }

            await connection.commit();
            transactionStarted = false;

            return {
                id: evaluation.id,
                pymeId: evaluation.pyme_id,
                domain: evaluation.dominio,
            };
        } catch (error) {
            if (transactionStarted) {
                try {
                    await connection.rollback();
                } catch {
                    // Se conserva el error original de la operación.
                }
            }

            throw error;
        } finally {
            connection.release();
        }
    }

}

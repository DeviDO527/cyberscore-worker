import type {
    Pool,
    RowDataPacket,
    ResultSetHeader,
} from 'mysql2/promise';

export interface PendingEvaluation {
    id: string;
    pymeId: string;
    domain: string;
    monthlyRevenue: number;
    operatingHours: number;
    currency: string;
}

interface EvaluationRow extends RowDataPacket {
    id: string;
    pyme_id: string;
    dominio: string;
    ingresos_mensuales: number | string;
    horas_operativas: number | string;
    moneda: string;
}

export class EvaluationRepository {
    private readonly supportedCurrencies = new Set([
        'COP',
        'USD',
        'EUR',
        'MXN',
    ]);

    constructor(private readonly pool: Pool) {}

    async claimNext(): Promise<PendingEvaluation | null> {
        const connection = await this.pool.getConnection();

        let transactionStarted = false;

        try {
            await connection.beginTransaction();
            transactionStarted = true;

            // Recuperar la evaluación pendiente y los datos económicos
            // de la PYME dentro de la misma transacción.
            const [rows] = await connection.query<EvaluationRow[]>(
                `SELECT
                    e.id,
                    e.pyme_id,
                    e.dominio,
                    p.ingresos_mensuales,
                    p.horas_operativas,
                    p.moneda
                 FROM evaluaciones e
                 INNER JOIN pymes p ON p.id = e.pyme_id
                 WHERE e.estado = 'queued'
                 ORDER BY e.iniciado_en ASC, e.id ASC
                 LIMIT 1
                 FOR UPDATE`,
            );

            const evaluation = rows[0];

            if (!evaluation) {
                await connection.commit();
                transactionStarted = false;

                return null;
            }

            // Validar y convertir los datos antes de reclamar
            // definitivamente la evaluación.
            const pendingEvaluation = this.mapEvaluation(evaluation);

            const [updateResult] =
                await connection.execute<ResultSetHeader>(
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

            return pendingEvaluation;

        } catch (error) {
            if (transactionStarted) {
                try {
                    await connection.rollback();
                } catch {
                    // Se conserva el error original.
                }
            }

            throw error;

        } finally {
            connection.release();
        }
    }

    private mapEvaluation(row: EvaluationRow): PendingEvaluation {
        const monthlyRevenue = Number(row.ingresos_mensuales);
        const operatingHours = Number(row.horas_operativas);
        const currency = row.moneda?.trim().toUpperCase();

        if (
            !Number.isFinite(monthlyRevenue) ||
            monthlyRevenue <= 0
        ) {
            throw new Error(
                `Los ingresos mensuales de la PYME ${row.pyme_id} no son válidos.`,
            );
        }

        if (
            !Number.isInteger(operatingHours) ||
            operatingHours < 1 ||
            operatingHours > 744
        ) {
            throw new Error(
                `Las horas operativas de la PYME ${row.pyme_id} no son válidas.`,
            );
        }

        if (
            !currency ||
            !this.supportedCurrencies.has(currency)
        ) {
            throw new Error(
                `La moneda de la PYME ${row.pyme_id} no es válida.`,
            );
        }

        return {
            id: row.id,
            pymeId: row.pyme_id,
            domain: row.dominio,
            monthlyRevenue,
            operatingHours,
            currency,
        };
    }
}
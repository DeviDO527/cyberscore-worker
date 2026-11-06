import { randomUUID } from 'node:crypto';

import type {
    Pool,
    PoolConnection,
    ResultSetHeader,
} from 'mysql2/promise';

export interface FindingToPersist {
    layer: string;
    severity: string;
    title: string;
    description: string;
    evidence?: string | null;
}

export interface EvaluationResult {
    evaluationId: string;
    pymeId: string;
    domain: string;
    score: number;
    level: string;
    layersSummary: Record<string, unknown>;
    findings: FindingToPersist[];
}

export class EvaluationResultRepository {
    constructor(private readonly pool: Pool) {}

    async complete(result: EvaluationResult): Promise<void> {
        this.validateResult(result);

        const connection = await this.pool.getConnection();
        let transactionStarted = false;

        try {
            await connection.beginTransaction();
            transactionStarted = true;

            // 1. Actualizar la evaluación.
            const [updateResult] =
                await connection.execute<ResultSetHeader>(
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

            // 2. Persistir los hallazgos en una sola operación.
            if (result.findings.length > 0) {
                const placeholders = result.findings
                    .map(() => '(?, ?, ?, ?, ?, ?, ?)')
                    .join(', ');
                const findingValues = result.findings.flatMap(finding => [
                    randomUUID(),
                    result.evaluationId.trim(),
                    finding.layer.trim(),
                    this.normalizeSeverity(finding.severity),
                    finding.title.trim(),
                    finding.description.trim(),
                    finding.evidence ?? null,
                ]);

                const [findingResult] =
                    await connection.execute<ResultSetHeader>(
                        `INSERT INTO hallazgos
                         (
                             id,
                             evaluacion_id,
                             capa,
                             severidad,
                             titulo,
                             descripcion,
                             evidencia
                         )
                         VALUES ${placeholders}`,
                        findingValues,
                    );

                this.ensureExpectedRowsUpdated(
                    findingResult,
                    result.findings.length,
                    'No fue posible guardar todos los hallazgos.',
                );
            }

            // 3. Registrar el historial del CyberScore.
            const [historyResult] =
                await connection.execute<ResultSetHeader>(
                    `INSERT INTO historial_scores
                     (
                         id,
                         dominio,
                         pyme_id,
                         score
                     )
                     VALUES (?, ?, ?, ?)`,
                    [
                        randomUUID(),
                        result.domain.trim(),
                        result.pymeId.trim(),
                        result.score,
                    ],
                );

            this.ensureOneRowUpdated(
                historyResult,
                'No fue posible registrar el historial del CyberScore.',
            );

            await connection.commit();
            transactionStarted = false;

        } catch (error) {
            if (transactionStarted) {
                await this.rollbackPreservingOriginalError(connection);
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

            const [updateResult] =
                await connection.execute<ResultSetHeader>(
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
                await this.rollbackPreservingOriginalError(connection);
            }

            throw error;

        } finally {
            connection.release();
        }
    }

    private validateResult(result: EvaluationResult): void {
        if (!result || typeof result !== 'object') {
            throw new Error('El resultado de la evaluación es obligatorio.');
        }

        this.validateEvaluationId(result.evaluationId);
        this.validateScore(result.score);
        this.validateLevel(result.level);
        this.validateText(result.pymeId, 'El identificador de la PYME');
        this.validateText(result.domain, 'El dominio');

        if (result.domain.trim().length > 255) {
            throw new Error('El dominio supera los 255 caracteres.');
        }

        if (
            result.layersSummary === null ||
            typeof result.layersSummary !== 'object' ||
            Array.isArray(result.layersSummary)
        ) {
            throw new Error(
                'El resumen de las capas debe ser un objeto válido.',
            );
        }

        if (!Array.isArray(result.findings)) {
            throw new TypeError('Los hallazgos deben proporcionarse como una lista.');
        }

        for (const finding of result.findings) {
            this.validateFinding(finding);
        }
    }

    private validateFinding(finding: FindingToPersist): void {
        if (!finding || typeof finding !== 'object') {
            throw new Error('El hallazgo proporcionado no es válido.');
        }

        this.validateText(finding.layer, 'La capa del hallazgo');
        this.validateText(finding.title, 'El título del hallazgo');
        this.validateText(finding.description, 'La descripción del hallazgo');

        if (finding.layer.trim().length > 50) {
            throw new Error('La capa supera los 50 caracteres.');
        }

        if (finding.title.trim().length > 255) {
            throw new Error('El título supera los 255 caracteres.');
        }

        if (
            finding.evidence !== undefined &&
            finding.evidence !== null &&
            typeof finding.evidence !== 'string'
        ) {
            throw new Error('La evidencia del hallazgo debe ser texto o null.');
        }

        if (finding.severity) {
            this.normalizeSeverity(finding.severity);
        } else {
            throw new Error('La severidad del hallazgo es obligatoria.');
        }
    }

    private normalizeSeverity(severity: string): string {
        const normalized = severity
            .trim()
            .toLowerCase()
            .normalize('NFD')
            .replace(/[\u0300-\u036f]/g, '');

        const severityMap: Record<string, string> = {
            low: 'BAJA',
            baja: 'BAJA',
            medium: 'MEDIA',
            media: 'MEDIA',
            high: 'ALTA',
            alta: 'ALTA',
            critical: 'CRITICA',
            critica: 'CRITICA',
        };

        const mappedSeverity = severityMap[normalized];

        if (!mappedSeverity) {
            throw new Error(
                `La severidad '${severity}' no está permitida.`,
            );
        }

        return mappedSeverity;
    }

    private validateEvaluationId(evaluationId: string): void {
        this.validateText(
            evaluationId,
            'El identificador de la evaluación',
        );
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
        this.validateText(level, 'El nivel de riesgo');
    }

    private validateText(value: string, name: string): void {
        if (
            typeof value !== 'string' ||
            value.trim().length === 0
        ) {
            throw new Error(`${name} es obligatorio.`);
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

    private ensureExpectedRowsUpdated(
        result: ResultSetHeader,
        expectedRows: number,
        message: string,
    ): void {
        if (result.affectedRows !== expectedRows) {
            throw new Error(message);
        }
    }

    private async rollbackPreservingOriginalError(
        connection: PoolConnection,
    ): Promise<void> {
        try {
            await connection.rollback();
        } catch {
            // Conservamos el error original de la operación.
        }

    }
}

import {
    calculateCyberScore,
    CYBERSCORE_FORMULA_VERSION,
} from './scoring-engine';

import {
    FINDING_RISK_MATRIX_VERSION,
} from './finding-risk-matrix';

import {
    assessFindingRisk,
} from './finding-risk-assessor';

import type {
    BusinessEconomicContext,
    FindingToAssess,
    FindingRiskAssessment,
} from './finding-risk-assessor';

// =====================================================
// ENTRADA DEL CALCULADOR
// =====================================================

export interface EvaluationScoreInput {
    findings: FindingToAssess[];
    businessContext: BusinessEconomicContext;
    layersSummary: Record<string, unknown>;
}

// =====================================================
// RESULTADO DEL CYBERSCORE
// =====================================================

export interface EvaluationScoreResult {
    score: number;
    rawScore: number;
    riskIndex: number;
    level: string;

    assessments: FindingRiskAssessment[];

    findings: FindingToAssess[];

    formulaVersion: string;
    matrixVersion: string;

    estimated: boolean;

    layersSummary: Record<string, unknown>;
}

// =====================================================
// CLASIFICACIÓN DE RIESGO
// =====================================================

function determineRiskLevel(score: number): string {
    if (score >= 80) {
        return 'Bajo';
    }

    if (score >= 60) {
        return 'Moderado';
    }

    if (score >= 40) {
        return 'Alto';
    }

    return 'Crítico';
}

// =====================================================
// VALIDACIÓN DE RESULTADOS DE LAS CAPAS
// =====================================================

function validateLayersSummary(
    layersSummary: Record<string, unknown>,
): void {
    if (
        layersSummary === null ||
        typeof layersSummary !== 'object' ||
        Array.isArray(layersSummary)
    ) {
        throw new Error(
            'El resumen de las capas no es válido.',
        );
    }

    const requiredLayers = [
        'dns',
        'tls',
        'headers',
    ] as const;

    for (const layer of requiredLayers) {
        const result = layersSummary[layer];

        if (
            result === null ||
            typeof result !== 'object' ||
            !('status' in result) ||
            result.status !== 'completed'
        ) {
            throw new Error(
                `La capa ${layer} no terminó correctamente. No se puede calcular un CyberScore definitivo.`,
            );
        }
    }
}

// =====================================================
// CALCULADOR GENERAL DE CYBERSCORE
// =====================================================

export function calculateEvaluationScore(
    input: EvaluationScoreInput,
): EvaluationScoreResult {

    if (!input || typeof input !== 'object') {
        throw new Error(
            'Los datos de la evaluación son obligatorios.',
        );
    }

    if (!Array.isArray(input.findings)) {
        throw new Error(
            'Los hallazgos deben proporcionarse como una lista.',
        );
    }

    validateLayersSummary(input.layersSummary);

    // =================================================
    // 1. EVALUAR INDIVIDUALMENTE LOS HALLAZGOS
    // =================================================

    const assessments: FindingRiskAssessment[] =
        input.findings.map(finding =>
            assessFindingRisk(
                finding,
                input.businessContext,
            ),
        );

    // =================================================
    // 2. CALCULAR EL ÍNDICE GENERAL Y EL CYBERSCORE
    // =================================================

    let rawScore: number;
    let riskIndex: number;

    if (assessments.length === 0) {

        // Convención operativa CyberScore:
        // si todas las capas terminaron correctamente
        // y no existen hallazgos, se asigna 100.

        rawScore = 100;
        riskIndex = 0;

    } else {

        const scoringResult = calculateCyberScore(
            assessments.map(assessment => assessment.risk),
        );

        rawScore = scoringResult.score;
        riskIndex = scoringResult.riskIndex;
    }

    // =================================================
    // 3. REDONDEAR LA PUNTUACIÓN
    // =================================================

    const score = Math.round(rawScore);

    // =================================================
    // 4. DETERMINAR EL NIVEL DE RIESGO
    // =================================================

    const level = determineRiskLevel(score);

    // =================================================
    // 5. CONSOLIDAR LOS SUPUESTOS METODOLÓGICOS
    // =================================================

    const assumptions = [
        'Los factores de riesgo se estiman mediante la matriz CyberScore PYME v1.0.',
        'Los valores económicos son estimaciones derivadas de los datos registrados por la PYME.',
        'La pérdida tolerable se estima como un día promedio de ingresos, utilizando 22 días operativos mensuales.',
        'Las horas de remediación son estimaciones internas de CyberScore.',
        'No se consideran conversiones entre monedas.',
        'La puntuación representa los hallazgos identificados dentro del alcance de evaluación.',
    ];

    for (const assessment of assessments) {
        assumptions.push(
            ...assessment.methodology.assumptions,
        );
    }

    const uniqueAssumptions = [
        ...new Set(assumptions),
    ];

    // =================================================
    // 6. CONSTRUIR EL RESUMEN METODOLÓGICO
    // =================================================

    const scoringSummary = {
        status: 'completed',

        formulaVersion: CYBERSCORE_FORMULA_VERSION,

        matrixVersion: FINDING_RISK_MATRIX_VERSION,

        estimated: true,

        score,
        rawScore,
        riskIndex,
        level,

        evaluatedFindings: assessments.length,

        currency: input.businessContext.currency
            .trim()
            .toUpperCase(),

        assumptions: uniqueAssumptions,

        emptyEvaluation: assessments.length === 0,

        emptyEvaluationMessage:
            assessments.length === 0
                ? 'No se identificaron hallazgos dentro del alcance evaluado. Esto no representa ausencia absoluta de riesgos.'
                : null,

        riskClassification: {
            low: '80-100',
            moderate: '60-79',
            high: '40-59',
            critical: '0-39',
        },
    };

    // =================================================
    // 7. DEVOLVER EL RESULTADO COMPLETO
    // =================================================

    return {
        score,
        rawScore,
        riskIndex,
        level,

        assessments,

        findings: input.findings,

        formulaVersion: CYBERSCORE_FORMULA_VERSION,

        matrixVersion: FINDING_RISK_MATRIX_VERSION,

        estimated: true,

        layersSummary: {
            ...input.layersSummary,
            scoring: scoringSummary,
        },
    };
}
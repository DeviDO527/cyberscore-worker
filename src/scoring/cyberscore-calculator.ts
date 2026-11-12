
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

export interface WhoisScoringInput {
    status: 'completed' | 'failed';
    daysUntilExpiration: number;
}

export interface VirusTotalScoringInput {
    status: 'completed' | 'unavailable' | 'failed';

    stats: {
        malicious: number;
        suspicious: number;
        harmless: number;
    };
}

export interface NmapScoringPort {
    port: number;
    protocol: string;
    state: string;
    serviceDetails: string;
}

export interface NmapScoringInput {
    status: string;
    openPorts: NmapScoringPort[];
}

export interface NmapPenaltyBreakdown {
    sensitivePortCount: number;
    sensitivePenalty: number;
    nonStandardPortCount: number;
    nonStandardPenalty: number;
}

export interface EvaluationScoreInput {
    findings: FindingToAssess[];
    businessContext: BusinessEconomicContext;
    layersSummary: Record<string, unknown>;
    whois?: WhoisScoringInput;
    virusTotal?: VirusTotalScoringInput;
    nmap?: NmapScoringInput;
}

// =====================================================
// RESULTADO DEL CYBERSCORE
// =====================================================

export interface EvaluationScoreResult {
    score: number;
    rawScore: number;
    baseScore: number;

    riskIndex: number;
    baseRiskIndex: number;

    whoisPenalty: number;
    virusTotalPenalty: number;
    nmapPenalty: number;
    nmapPenaltyBreakdown: NmapPenaltyBreakdown;

    virusTotalReputation: string;

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
// VALIDACIÓN DE CONTADORES DE VIRUSTOTAL
// =====================================================

function normalizeVirusTotalCount(value: number): number {
    if (
        typeof value !== 'number' ||
        !Number.isFinite(value)
    ) {
        return 0;
    }

    return Math.max(0, Math.floor(value));
}

const NMAP_SENSITIVE_PORTS = new Set([
    21,   // FTP
    22,   // SSH
    23,   // Telnet
    3306, // MySQL
    3389, // RDP
]);

const NMAP_SENSITIVE_PORT_PENALTY = 20;
const NMAP_NON_STANDARD_PORT_PENALTY = 10;

function calculateNmapPenalty(
    nmap: NmapScoringInput | undefined,
): {
    penalty: number;
    breakdown: NmapPenaltyBreakdown;
} {
    const breakdown: NmapPenaltyBreakdown = {
        sensitivePortCount: 0,
        sensitivePenalty: 0,
        nonStandardPortCount: 0,
        nonStandardPenalty: 0,
    };

    if (nmap?.status !== 'completed') {
        return { penalty: 0, breakdown };
    }

    if (!Array.isArray(nmap.openPorts)) {
        throw new TypeError(
            'Los puertos abiertos de Nmap deben proporcionarse como una lista.',
        );
    }

    for (const port of nmap.openPorts) {
        if (!port || typeof port !== 'object') {
            throw new Error('El puerto Nmap proporcionado no es válido.');
        }

        if (port.state !== 'open') {
            continue;
        }

        if (
            !Number.isInteger(port.port) ||
            port.port < 1 ||
            port.port > 65_535 ||
            typeof port.protocol !== 'string' ||
            !port.protocol.trim() ||
            typeof port.serviceDetails !== 'string'
        ) {
            throw new Error(
                'El hallazgo de puerto Nmap no contiene datos válidos.',
            );
        }

        if (NMAP_SENSITIVE_PORTS.has(port.port)) {
            breakdown.sensitivePortCount++;
            breakdown.sensitivePenalty +=
                NMAP_SENSITIVE_PORT_PENALTY;
        } else if (port.port !== 80 && port.port !== 443) {
            breakdown.nonStandardPortCount++;
            breakdown.nonStandardPenalty +=
                NMAP_NON_STANDARD_PORT_PENALTY;
        }
    }

    return {
        penalty:
            breakdown.sensitivePenalty +
            breakdown.nonStandardPenalty,
        breakdown,
    };
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
        throw new TypeError(
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
    // 2. CALCULAR LA PUNTUACIÓN BASE
    // =================================================

    let baseRawScore: number;
    let baseRiskIndex: number;

    if (assessments.length === 0) {
        // Si todas las capas finalizaron correctamente
        // y no existen hallazgos, se asigna 100.

        baseRawScore = 100;
        baseRiskIndex = 0;

    } else {
        const scoringResult = calculateCyberScore(
            assessments.map(assessment => assessment.risk),
        );

        baseRawScore = scoringResult.score;
        baseRiskIndex = scoringResult.riskIndex;
    }

    // =================================================
    // 3. PENALIZACIÓN WHOIS
    // =================================================

    const daysUntilExpiration =
        input.whois?.daysUntilExpiration;

    const whoisPenalty =
        input.whois?.status === 'completed' &&
        typeof daysUntilExpiration === 'number' &&
        Number.isFinite(daysUntilExpiration) &&
        daysUntilExpiration > 0 &&
        daysUntilExpiration < 30
            ? 15
            : 0;

    // =================================================
    // 4. PENALIZACIÓN VIRUSTOTAL
    // =================================================

    const maliciousCount = normalizeVirusTotalCount(
        input.virusTotal?.stats.malicious ?? 0,
    );

    const suspiciousCount = normalizeVirusTotalCount(
        input.virusTotal?.stats.suspicious ?? 0,
    );

    const harmlessCount = normalizeVirusTotalCount(
        input.virusTotal?.stats.harmless ?? 0,
    );

    const totalVirusTotalAlerts =
        maliciousCount + suspiciousCount;

    // La penalización solo se aplica cuando la consulta
    // VirusTotal terminó correctamente.

    const virusTotalPenalty =
        input.virusTotal?.status === 'completed'
            ? totalVirusTotalAlerts * 25
            : 0;

    const {
        penalty: nmapPenalty,
        breakdown: nmapPenaltyBreakdown,
    } = calculateNmapPenalty(input.nmap);

    // =================================================
    // 5. TEXTO DE REPUTACIÓN VIRUSTOTAL
    // =================================================

    let virusTotalReputation = 'Consulta no disponible';

    if (input.virusTotal?.status === 'completed') {
        if (totalVirusTotalAlerts > 0) {
            virusTotalReputation =
                `¡ALERTA CRÍTICA! Marcado por ${totalVirusTotalAlerts} motores de seguridad.`;
        } else {
            virusTotalReputation =
                `Dominio Limpio (Confirmado por ${harmlessCount} motores de seguridad).`;
        }
    }

    // =================================================
    // 6. CALCULAR LA PUNTUACIÓN FINAL
    // =================================================

    const baseScore = Math.round(baseRawScore);

    const totalPenalty =
        whoisPenalty + virusTotalPenalty + nmapPenalty;

    const rawScore = Math.max(
        baseRawScore - totalPenalty,
        0,
    );

    const score = Math.round(rawScore);

    const riskIndex = 1 - rawScore / 100;

    // =================================================
    // 7. DETERMINAR EL NIVEL DE RIESGO
    // =================================================

    const level = determineRiskLevel(score);

    // =================================================
    // 8. CONSOLIDAR LOS SUPUESTOS METODOLÓGICOS
    // =================================================

    const assumptions = [
        'Los factores de riesgo se estiman mediante la matriz CyberScore PYME v1.1.',
        'Los valores económicos son estimaciones derivadas de los datos registrados por la PYME.',
        'La pérdida tolerable se estima como un día promedio de ingresos, utilizando 22 días operativos mensuales.',
        'Las horas de remediación son estimaciones internas de CyberScore.',
        'No se consideran conversiones entre monedas.',
        'La puntuación representa los hallazgos identificados dentro del alcance de evaluación.',
        'VirusTotal utiliza la cantidad de motores maliciosos y sospechosos para calcular una penalización independiente.',
        ...(input.nmap?.status === 'completed'
            ? [
                'Nmap descuenta 20 puntos por cada puerto sensible abierto (21, 22, 23, 3306 y 3389) y 10 por cada otro puerto abierto, excepto 80 y 443.',
                'La exposición de un puerto no demuestra por sí misma una vulnerabilidad ni la explotabilidad del servicio.',
            ]
            : []),
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
    // 9. CONSTRUIR EL RESUMEN METODOLÓGICO
    // =================================================

    const scoringSummary = {
        status: 'completed',

        formulaVersion: CYBERSCORE_FORMULA_VERSION,
        matrixVersion: FINDING_RISK_MATRIX_VERSION,

        estimated: true,

        score,
        rawScore,
        baseScore,

        riskIndex,
        baseRiskIndex,

        whoisPenalty,
        whoisStatus: input.whois?.status ?? 'not_provided',
        whoisDaysUntilExpiration: daysUntilExpiration ?? null,

        virusTotalPenalty,
        nmapPenalty,
        nmapStatus: input.nmap?.status ?? 'not_provided',
        nmapPenaltyBreakdown,
        virusTotalStatus:
            input.virusTotal?.status ?? 'not_provided',
        virusTotalMalicious: maliciousCount,
        virusTotalSuspicious: suspiciousCount,
        virusTotalHarmless: harmlessCount,
        virusTotalTotalAlerts: totalVirusTotalAlerts,
        virusTotalReputation,

        totalPenalty,

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
    // 10. DEVOLVER EL RESULTADO COMPLETO
    // =================================================

    return {
        score,
        rawScore,
        baseScore,

        riskIndex,
        baseRiskIndex,

        whoisPenalty,
        virusTotalPenalty,
        nmapPenalty,
        nmapPenaltyBreakdown,

        virusTotalReputation,

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

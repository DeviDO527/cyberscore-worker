import {
    calculateFindingRisk,
    calculateLikelihood,
    calculateTechnicalImpact,
    CYBERSCORE_FORMULA_VERSION,
} from './scoring-engine';

import {
    FINDING_RISK_MATRIX_VERSION,
    resolveFindingRiskProfile,
} from './finding-risk-matrix';

import type {
    FindingIdentification,
    FindingRiskProfile,
} from './finding-risk-matrix';

import {
    calculateEconomicImpactForFinding,
} from './economic-impact-calculator';

import type {
    EconomicImpactResult,
} from './economic-impact-calculator';

// =====================================================
// CONTEXTO ECONÓMICO DE LA PYME
// =====================================================

export interface BusinessEconomicContext {
    monthlyRevenue: number;
    operatingHours: number;
    currency: string;
}

// =====================================================
// HALLAZGO A EVALUAR
// =====================================================

export interface FindingToAssess extends FindingIdentification {
    severity?: string;
    evidence?: string | null;
}

// =====================================================
// RESULTADO DE LA EVALUACIÓN INDIVIDUAL
// =====================================================

export interface FindingRiskAssessment {
    profileId: string;

    likelihood: number;

    technicalImpact: number;

    economicImpact: EconomicImpactResult;

    risk: number;

    evidence: string | null;

    profile: FindingRiskProfile;

    methodology: {
        formulaVersion: string;
        matrixVersion: string;
        estimated: boolean;
        assumptions: string[];
    };
}

// =====================================================
// EVALUADOR DE RIESGOS
// =====================================================

export function assessFindingRisk(
    finding: FindingToAssess,
    businessContext: BusinessEconomicContext,
): FindingRiskAssessment {

    // 1. Identificar el perfil metodológico.
    const profile = resolveFindingRiskProfile(finding);

    // 2. Calcular la probabilidad.
    const likelihood = calculateLikelihood(
        profile.likelihood,
    );

    // 3. Calcular el impacto técnico.
    const technicalImpact = calculateTechnicalImpact(
        profile.technicalImpact,
    );

    // 4. Calcular el impacto económico.
    const economicImpact = calculateEconomicImpactForFinding({
        monthlyRevenue: businessContext.monthlyRevenue,
        operatingHours: businessContext.operatingHours,
        currency: businessContext.currency,
        interruptionHours: profile.interruptionHours,
        remediationHours: profile.remediationHours,
    });

    // 5. Calcular el riesgo individual.
    const risk = calculateFindingRisk({
        likelihood,
        technicalImpact,
        economicImpact: economicImpact.impact,
    });

    // 6. Documentar los supuestos y versiones metodológicas.
    const assumptions = [
        ...profile.assumptions,
        ...economicImpact.assumptions,
        'Los factores de riesgo corresponden a estimaciones de la matriz CyberScore PYME.',
        'Los resultados económicos no representan pérdidas observadas.',
    ];

    return {
        profileId: profile.id,

        likelihood,

        technicalImpact,

        economicImpact,

        risk,

        evidence: finding.evidence ?? null,

        profile,

        methodology: {
            formulaVersion: CYBERSCORE_FORMULA_VERSION,
            matrixVersion: FINDING_RISK_MATRIX_VERSION,
            estimated: true,
            assumptions,
        },
    };
}
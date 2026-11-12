import { describe, it, expect } from '@jest/globals';

import {
    assessFindingRisk,
} from '../src/scoring/finding-risk-assessor';

import {
    FINDING_RISK_MATRIX,
    FINDING_RISK_MATRIX_VERSION,
} from '../src/scoring/finding-risk-matrix';

import {
    calculateFindingRisk,
    calculateLikelihood,
    calculateTechnicalImpact,
} from '../src/scoring/scoring-engine';

describe('FindingRiskAssessor', () => {

    const businessContext = {
        monthlyRevenue: 30_000_000,
        operatingHours: 300,
        currency: 'COP',
    };

    const finding = {
        layer: 'headers',
        severity: 'medium',
        title: 'Cabecera de seguridad ausente',
        description: 'No se encontró Strict-Transport-Security (HSTS).',
        evidence: '{"statusCode":200}',
    };

    it('identifica el perfil metodológico del hallazgo', () => {
        const result = assessFindingRisk(
            finding,
            businessContext,
        );

        expect(result.profileId).toBe('HTTP_HSTS_MISSING');
    });

    it('calcula correctamente la probabilidad', () => {
        const result = assessFindingRisk(
            finding,
            businessContext,
        );

        const profile = FINDING_RISK_MATRIX.find(
            item => item.id === 'HTTP_HSTS_MISSING',
        )!;

        expect(result.likelihood).toBe(
            calculateLikelihood(profile.likelihood),
        );
    });

    it('calcula correctamente el impacto técnico', () => {
        const result = assessFindingRisk(
            finding,
            businessContext,
        );

        const profile = FINDING_RISK_MATRIX.find(
            item => item.id === 'HTTP_HSTS_MISSING',
        )!;

        expect(result.technicalImpact).toBe(
            calculateTechnicalImpact(profile.technicalImpact),
        );
    });

    it('calcula el impacto económico utilizando los datos de la PYME', () => {
        const result = assessFindingRisk(
            finding,
            businessContext,
        );

        expect(result.economicImpact.hourlyIncome).toBe(100_000);
        expect(result.economicImpact.currency).toBe('COP');
        expect(result.economicImpact.estimated).toBe(true);
    });

    it('calcula correctamente el riesgo individual', () => {
        const result = assessFindingRisk(
            finding,
            businessContext,
        );

        const expectedRisk = calculateFindingRisk({
            likelihood: result.likelihood,
            technicalImpact: result.technicalImpact,
            economicImpact: result.economicImpact.impact,
        });

        expect(result.risk).toBeCloseTo(expectedRisk);
    });

    it('conserva la evidencia original del hallazgo', () => {
        const result = assessFindingRisk(
            finding,
            businessContext,
        );

        expect(result.evidence).toBe(finding.evidence);
    });

    it('documenta las versiones metodológicas utilizadas', () => {
        const result = assessFindingRisk(
            finding,
            businessContext,
        );

        expect(result.methodology.formulaVersion).toBe('1.1');
        expect(result.methodology.matrixVersion).toBe(
            FINDING_RISK_MATRIX_VERSION,
        );

        expect(result.methodology.estimated).toBe(true);
        expect(result.methodology.assumptions.length).toBeGreaterThan(0);
    });

    it.each(FINDING_RISK_MATRIX)(
        'evalúa el perfil $id',
        (profile) => {
            const term = profile.matchTerms[0];

            const testFinding = {
                layer: profile.layer,
                title: `Hallazgo ${profile.id}`,
                description: `Configuración detectada: ${term}`,
                evidence: null,
            };

            const result = assessFindingRisk(
                testFinding,
                businessContext,
            );

            expect(result.profileId).toBe(profile.id);
            expect(result.risk).toBeGreaterThanOrEqual(0);
            expect(result.risk).toBeLessThanOrEqual(1);
        },
    );

    it('rechaza hallazgos sin perfil metodológico', () => {
        expect(() =>
            assessFindingRisk(
                {
                    layer: 'dns',
                    title: 'Hallazgo desconocido',
                    description: 'Configuración no contemplada.',
                    evidence: null,
                },
                businessContext,
            ),
        ).toThrow('No existe un perfil metodológico');
    });

    it('rechaza datos económicos inválidos', () => {
        expect(() =>
            assessFindingRisk(
                finding,
                {
                    ...businessContext,
                    monthlyRevenue: 0,
                },
            ),
        ).toThrow();
    });
});

import { describe, it, expect } from '@jest/globals';

import {
    calculateEvaluationScore,
} from '../src/scoring/cyberscore-calculator';

describe('CyberScoreCalculator', () => {

    const businessContext = {
        monthlyRevenue: 30_000_000,
        operatingHours: 300,
        currency: 'COP',
    };

    const layersSummary = {
        dns: {
            status: 'completed',
            findings: 0,
        },
        tls: {
            status: 'completed',
            findings: 0,
        },
        headers: {
            status: 'completed',
            findings: 1,
        },
    };

    const findings = [
        {
            layer: 'headers',
            severity: 'medium',
            title: 'Cabecera de seguridad ausente',
            description: 'No se encontró Strict-Transport-Security (HSTS).',
            evidence: '{"statusCode":200}',
        },
    ];

    it('calcula el CyberScore a partir de los riesgos individuales', () => {
        const result = calculateEvaluationScore({
            findings,
            businessContext,
            layersSummary,
        });

        expect(result.score).toBeGreaterThanOrEqual(0);
        expect(result.score).toBeLessThanOrEqual(100);
        expect(Number.isInteger(result.score)).toBe(true);
    });

    it('calcula correctamente el índice general de riesgo', () => {
        const result = calculateEvaluationScore({
            findings,
            businessContext,
            layersSummary,
        });

        expect(result.riskIndex).toBeGreaterThanOrEqual(0);
        expect(result.riskIndex).toBeLessThanOrEqual(1);
    });

    it('calcula el CyberScore mediante la fórmula establecida', () => {
        const result = calculateEvaluationScore({
            findings,
            businessContext,
            layersSummary,
        });

        expect(result.rawScore).toBeCloseTo(
            100 * (1 - result.riskIndex),
        );

        expect(result.score).toBe(
            Math.round(result.rawScore),
        );
    });

    it('conserva las evaluaciones individuales de los hallazgos', () => {
        const result = calculateEvaluationScore({
            findings,
            businessContext,
            layersSummary,
        });

        expect(result.assessments).toHaveLength(1);
        expect(result.assessments[0]?.profileId).toBe(
            'HTTP_HSTS_MISSING',
        );
    });

    it('conserva la evidencia de los hallazgos', () => {
        const result = calculateEvaluationScore({
            findings,
            businessContext,
            layersSummary,
        });

        expect(result.findings).toEqual(findings);
    });

    it('incluye las versiones metodológicas en el resultado', () => {
        const result = calculateEvaluationScore({
            findings,
            businessContext,
            layersSummary,
        });

        expect(result.formulaVersion).toBe('1.0');
        expect(result.matrixVersion).toBe('1.0');
        expect(result.estimated).toBe(true);
    });

    it('incluye la información metodológica en el resumen de capas', () => {
        const result = calculateEvaluationScore({
            findings,
            businessContext,
            layersSummary,
        });

        expect(result.layersSummary).toHaveProperty('dns');
        expect(result.layersSummary).toHaveProperty('tls');
        expect(result.layersSummary).toHaveProperty('headers');
        expect(result.layersSummary).toHaveProperty('scoring');
    });

    it('asigna un CyberScore de 100 cuando no existen hallazgos y todas las capas finalizaron correctamente', () => {
        const result = calculateEvaluationScore({
            findings: [],
            businessContext,
            layersSummary: {
                dns: { status: 'completed', findings: 0 },
                tls: { status: 'completed', findings: 0 },
                headers: { status: 'completed', findings: 0 },
            },
        });

        expect(result.score).toBe(100);
        expect(result.rawScore).toBe(100);
        expect(result.riskIndex).toBe(0);
        expect(result.assessments).toHaveLength(0);
    });

    it('no asigna una puntuación si alguna capa no finalizó correctamente', () => {
        expect(() =>
            calculateEvaluationScore({
                findings,
                businessContext,
                layersSummary: {
                    ...layersSummary,
                    tls: {
                        status: 'failed',
                        findings: 0,
                    },
                },
            }),
        ).toThrow();
    });

    it('no asigna 100 cuando alguna capa falla y no existen hallazgos', () => {
        expect(() =>
            calculateEvaluationScore({
                findings: [],
                businessContext,
                layersSummary: {
                    dns: { status: 'completed', findings: 0 },
                    tls: { status: 'failed', findings: 0 },
                    headers: { status: 'completed', findings: 0 },
                },
            }),
        ).toThrow();
    });

    it('rechaza hallazgos que no tienen perfil metodológico', () => {
        expect(() =>
            calculateEvaluationScore({
                findings: [
                    {
                        layer: 'dns',
                        severity: 'medium',
                        title: 'Hallazgo desconocido',
                        description: 'Configuración no contemplada.',
                        evidence: null,
                    },
                ],
                businessContext,
                layersSummary,
            }),
        ).toThrow();
    });

    it('rechaza datos económicos inválidos', () => {
        expect(() =>
            calculateEvaluationScore({
                findings,
                businessContext: {
                    ...businessContext,
                    monthlyRevenue: 0,
                },
                layersSummary,
            }),
        ).toThrow();
    });
});
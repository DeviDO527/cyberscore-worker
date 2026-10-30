import { describe, it, expect } from '@jest/globals';

import {
    calculateEconomicImpactForFinding,
} from '../src/scoring/economic-impact-calculator';

describe('EconomicImpactCalculator', () => {

    const baseInput = {
        monthlyRevenue: 30_000_000,
        operatingHours: 300,
        currency: 'COP',
        interruptionHours: 0,
        remediationHours: 0.5,
    };

    it('calcula correctamente el ingreso por hora', () => {
        const result = calculateEconomicImpactForFinding(baseInput);

        expect(result.hourlyIncome).toBe(100_000);
    });

    it('estima la pérdida tolerable como un día de ingresos', () => {
        const result = calculateEconomicImpactForFinding(baseInput);

        expect(result.tolerableLoss).toBeCloseTo(
            30_000_000 / 22,
        );
    });

    it('calcula el costo de recuperación según las horas de remediación', () => {
        const result = calculateEconomicImpactForFinding(baseInput);

        expect(result.recoveryCost).toBe(50_000);
    });

    it('calcula las pérdidas por interrupción', () => {
        const result = calculateEconomicImpactForFinding({
            ...baseInput,
            interruptionHours: 2,
        });

        expect(result.interruptionLoss).toBe(200_000);
    });

    it('calcula la pérdida potencial total', () => {
        const result = calculateEconomicImpactForFinding({
            ...baseInput,
            interruptionHours: 2,
        });

        expect(result.potentialLoss).toBe(250_000);
    });

    it('calcula el impacto económico utilizando la fórmula CyberScore', () => {
        const result = calculateEconomicImpactForFinding(baseInput);

        const expected =
            (50_000 / (30_000_000 / 22)) * 10;

        expect(result.impact).toBeCloseTo(expected);
    });

    it('limita el impacto económico máximo a 10', () => {
        const result = calculateEconomicImpactForFinding({
            ...baseInput,
            interruptionHours: 1000,
            remediationHours: 20,
        });

        expect(result.impact).toBe(10);
    });

    it('conserva la moneda de la PYME', () => {
        const result = calculateEconomicImpactForFinding(baseInput);

        expect(result.currency).toBe('COP');
    });

    it('documenta los supuestos económicos utilizados', () => {
        const result = calculateEconomicImpactForFinding(baseInput);

        expect(result.assumptions.length).toBeGreaterThan(0);
        expect(result.estimated).toBe(true);
    });

    it('rechaza ingresos mensuales iguales a cero', () => {
        expect(() =>
            calculateEconomicImpactForFinding({
                ...baseInput,
                monthlyRevenue: 0,
            }),
        ).toThrow();
    });

    it('rechaza horas operativas iguales a cero', () => {
        expect(() =>
            calculateEconomicImpactForFinding({
                ...baseInput,
                operatingHours: 0,
            }),
        ).toThrow();
    });

    it('rechaza horas de remediación negativas', () => {
        expect(() =>
            calculateEconomicImpactForFinding({
                ...baseInput,
                remediationHours: -1,
            }),
        ).toThrow();
    });

    it('rechaza horas de interrupción negativas', () => {
        expect(() =>
            calculateEconomicImpactForFinding({
                ...baseInput,
                interruptionHours: -1,
            }),
        ).toThrow();
    });
});
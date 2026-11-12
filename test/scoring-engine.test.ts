import { describe, it, expect} from '@jest/globals';
import {
  calculateLikelihood,
  calculateTechnicalImpact,
  calculateEconomicImpact,
  calculateFindingRisk,
  calculateCyberScore,
} from '../src/scoring/scoring-engine';

describe('ScoringEngine - CyberScore Formula v1.0', () => {
  describe('calculateLikelihood', () => {
    it('debe normalizar los cuatro factores de probabilidad', () => {
      const result = calculateLikelihood({
        discovery: 9,
        exploitation: 9,
        awareness: 9,
        detectionDifficulty: 9,
      });

      expect(result).toBe(1);
    });

    it('debe devolver 0 cuando todos los factores son 0', () => {
      const result = calculateLikelihood({
        discovery: 0,
        exploitation: 0,
        awareness: 0,
        detectionDifficulty: 0,
      });

      expect(result).toBe(0);
    });

    it('debe calcular correctamente un resultado intermedio', () => {
      const result = calculateLikelihood({
        discovery: 9,
        exploitation: 9,
        awareness: 6,
        detectionDifficulty: 6,
      });

      expect(result).toBeCloseTo(30 / 36);
    });

    it('debe rechazar valores fuera del rango permitido', () => {
      expect(() =>
        calculateLikelihood({
          discovery: 10,
          exploitation: 9,
          awareness: 9,
          detectionDifficulty: 9,
        }),
      ).toThrow();
    });

    it('debe rechazar NaN en los factores de probabilidad', () => {
      expect(() =>
        calculateLikelihood({
          discovery: Number.NaN,
          exploitation: 9,
          awareness: 9,
          detectionDifficulty: 9,
        }),
      ).toThrow(RangeError);
    });

    it('debe rechazar Infinity en los factores de probabilidad', () => {
      expect(() =>
        calculateLikelihood({
          discovery: 9,
          exploitation: 9,
          awareness: Number.POSITIVE_INFINITY,
          detectionDifficulty: 9,
        }),
      ).toThrow(RangeError);
    });

  });

  describe('calculateTechnicalImpact', () => {
    it('debe convertir la suma máxima de las dimensiones a 10', () => {
      const result = calculateTechnicalImpact({
        confidentiality: 9,
        integrity: 9,
        availability: 9,
        accountability: 9,
      });

      expect(result).toBe(10);
    });

    it('debe devolver 0 cuando todas las dimensiones son 0', () => {
      const result = calculateTechnicalImpact({
        confidentiality: 0,
        integrity: 0,
        availability: 0,
        accountability: 0,
      });

      expect(result).toBe(0);
    });

    it('debe rechazar dimensiones fuera del rango permitido', () => {
      expect(() =>
        calculateTechnicalImpact({
          confidentiality: 9,
          integrity: 9,
          availability: 9,
          accountability: -1,
        }),
      ).toThrow();
    });

    it('debe rechazar NaN en las dimensiones técnicas', () => {
      expect(() =>
        calculateTechnicalImpact({
          confidentiality: Number.NaN,
          integrity: 9,
          availability: 9,
          accountability: 9,
        }),
      ).toThrow(RangeError);
    });

    it('debe rechazar Infinity en las dimensiones técnicas', () => {
      expect(() =>
        calculateTechnicalImpact({
          confidentiality: 9,
          integrity: 9,
          availability: Number.POSITIVE_INFINITY,
          accountability: 9,
        }),
      ).toThrow(RangeError);
    });

  });

  describe('calculateEconomicImpact', () => {
    it('debe calcular la pérdida potencial y el impacto económico', () => {
      const result = calculateEconomicImpact({
        hourlyIncome: 100_000,
        interruptionHours: 8,
        recoveryCost: 0,
        tolerableLoss: 10_000_000,
      });

      expect(result.potentialLoss).toBe(800_000);
      expect(result.impact).toBeCloseTo(0.8);
    });

    it('debe limitar el impacto económico a 10', () => {
      const result = calculateEconomicImpact({
        hourlyIncome: 1_000_000,
        interruptionHours: 20,
        recoveryCost: 5_000_000,
        tolerableLoss: 10_000_000,
      });

      expect(result.impact).toBe(10);
    });

    it('debe rechazar una pérdida tolerable igual a 0', () => {
      expect(() =>
        calculateEconomicImpact({
          hourlyIncome: 100_000,
          interruptionHours: 8,
          recoveryCost: 0,
          tolerableLoss: 0,
        }),
      ).toThrow();
    });

    it('debe rechazar valores económicos negativos', () => {
      expect(() =>
        calculateEconomicImpact({
          hourlyIncome: -1,
          interruptionHours: 1,
          recoveryCost: 0,
          tolerableLoss: 100,
        })
      ).toThrow(RangeError);
    });

    it('debe rechazar una pérdida económica que exceda el rango numérico', () => {
      expect(() =>
        calculateEconomicImpact({
          hourlyIncome: Number.MAX_VALUE,
          interruptionHours: 2,
          recoveryCost: 0,
          tolerableLoss: 100,
        })
      ).toThrow(
        'La pérdida económica potencial excede el rango numérico permitido.'
      );
    });

    it('debe rechazar un ingreso por hora no finito', () => {
      expect(() =>
        calculateEconomicImpact({
          hourlyIncome: Number.POSITIVE_INFINITY,
          interruptionHours: 8,
          recoveryCost: 0,
          tolerableLoss: 10_000_000,
        }),
      ).toThrow(RangeError);
    });

    it('debe rechazar una duración de interrupción negativa', () => {
      expect(() =>
        calculateEconomicImpact({
          hourlyIncome: 100_000,
          interruptionHours: -1,
          recoveryCost: 0,
          tolerableLoss: 10_000_000,
        }),
      ).toThrow(RangeError);
    });

    it('debe rechazar un costo de recuperación no finito', () => {
      expect(() =>
        calculateEconomicImpact({
          hourlyIncome: 100_000,
          interruptionHours: 8,
          recoveryCost: Number.NaN,
          tolerableLoss: 10_000_000,
        }),
      ).toThrow(RangeError);
    });

    it('debe rechazar una pérdida tolerable no finita', () => {
      expect(() =>
        calculateEconomicImpact({
          hourlyIncome: 100_000,
          interruptionHours: 8,
          recoveryCost: 0,
          tolerableLoss: Number.POSITIVE_INFINITY,
        }),
      ).toThrow(RangeError);
    });

  });

  describe('calculateFindingRisk', () => {
    it('debe aplicar los pesos 40 % técnico y 60 % económico', () => {
      const result = calculateFindingRisk({
        likelihood: 0.7,
        technicalImpact: 8,
        economicImpact: 0.8,
      });
    
      expect(result).toBeCloseTo(0.2576);
    });


    it('debe devolver 0 cuando la probabilidad es 0', () => {
      const result = calculateFindingRisk({
        likelihood: 0,
        technicalImpact: 10,
        economicImpact: 10,
      });

      expect(result).toBe(0);
    });

    it('debe devolver 1 cuando todos los componentes alcanzan su máximo', () => {
      const result = calculateFindingRisk({
        likelihood: 1,
        technicalImpact: 10,
        economicImpact: 10,
      });

      expect(result).toBe(1);
    });

    it('debe rechazar valores fuera de sus rangos', () => {
      expect(() =>
        calculateFindingRisk({
          likelihood: 1.5,
          technicalImpact: 10,
          economicImpact: 10,
        }),
      ).toThrow();
    });

    it('debe rechazar una probabilidad no finita', () => {
      expect(() =>
        calculateFindingRisk({
          likelihood: Number.NaN,
          technicalImpact: 8,
          economicImpact: 5,
        }),
      ).toThrow(RangeError);
    });

    it('debe rechazar un impacto técnico superior a 10', () => {
      expect(() =>
        calculateFindingRisk({
          likelihood: 0.5,
          technicalImpact: 11,
          economicImpact: 5,
        }),
      ).toThrow(RangeError);
    });

    it('debe rechazar un impacto económico negativo', () => {
      expect(() =>
        calculateFindingRisk({
          likelihood: 0.5,
          technicalImpact: 8,
          economicImpact: -1,
        }),
      ).toThrow(RangeError);
    });

  });

  describe('calculateCyberScore', () => {
  
    it('debe promediar los riesgos de varios hallazgos', () => {
      const result = calculateCyberScore([0.2, 0.4]);

      expect(result.riskIndex).toBeCloseTo(0.3);
      expect(result.score).toBeCloseTo(70);
    });

    it('debe devolver 100 cuando los riesgos incluidos son 0', () => {
      const result = calculateCyberScore([0, 0]);

      expect(result.riskIndex).toBe(0);
      expect(result.score).toBe(100);
    });

    it('debe rechazar riesgos fuera del rango normalizado', () => {
      expect(() => calculateCyberScore([1.2])).toThrow();
    });

    it('debe rechazar una lista vacía de riesgos', () => {
      expect(() => calculateCyberScore([])).toThrow();
    });

    it('debe devolver score 0 cuando el índice de riesgo es 1', () => {
      const result = calculateCyberScore([1]);

      expect(result.riskIndex).toBe(1);
      expect(result.score).toBe(0);
    });

    it('debe incluir la versión de la fórmula en el resultado', () => {
      const result = calculateCyberScore([0.2, 0.4]);
    
      expect(result.formulaVersion).toBe('1.1');
    });

  });
});

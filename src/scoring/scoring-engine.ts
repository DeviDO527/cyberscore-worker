export const CYBERSCORE_FORMULA_VERSION = '1.0';

interface LikelihoodFactors {
  discovery: number;
  exploitation: number;
  awareness: number;
  detectionDifficulty: number;
}

interface TechnicalImpactFactors {
  confidentiality: number;
  integrity: number;
  availability: number;
  accountability: number;
}

interface EconomicImpactInput {
  hourlyIncome: number;
  interruptionHours: number;
  recoveryCost: number;
  tolerableLoss: number;
}

interface FindingRiskInput {
  likelihood: number;
  technicalImpact: number;
  economicImpact: number;
}

interface CyberScoreResult {
  score: number;
  riskIndex: number;
  formulaVersion: string;
}

interface EconomicImpactResult {
  potentialLoss: number;
  impact: number;
}

/**
 * Valida que un valor numérico esté dentro de un rango inclusivo.
 */
function validateRange(
  value: number,
  name: string,
  min: number,
  max: number,
): void {
  if (!Number.isFinite(value) || value < min || value > max) {
    throw new RangeError(
      `${name} debe ser un número entre ${min} y ${max}.`,
    );
  }
}

/**
 * Valida valores económicos finitos y no negativos.
 */
function validateNonNegative(value: number, name: string): void {
  if (!Number.isFinite(value) || value < 0) {
    throw new RangeError(
      `${name} debe ser un número finito no negativo.`,
    );
  }
}

/**
 * Lᵢ = (Dᵢ + Xᵢ + Aᵢ + Mᵢ) / 36
 */
export function calculateLikelihood(
  factors: LikelihoodFactors,
): number {
  const values = [
    ['discovery', factors.discovery],
    ['exploitation', factors.exploitation],
    ['awareness', factors.awareness],
    ['detectionDifficulty', factors.detectionDifficulty],
  ] as const;

  for (const [name, value] of values) {
    validateRange(value, name, 0, 9);
  }

  return (
    factors.discovery +
    factors.exploitation +
    factors.awareness +
    factors.detectionDifficulty
  ) / 36;
}

/**
 * Tᵢ = ((Cᵢ + Iᵢ + Aᵢ + ACᵢ) / 36) × 10
 */
export function calculateTechnicalImpact(
  factors: TechnicalImpactFactors,
): number {
  const values = [
    ['confidentiality', factors.confidentiality],
    ['integrity', factors.integrity],
    ['availability', factors.availability],
    ['accountability', factors.accountability],
  ] as const;

  for (const [name, value] of values) {
    validateRange(value, name, 0, 9);
  }

  return (
    (
      factors.confidentiality +
      factors.integrity +
      factors.availability +
      factors.accountability
    ) / 36
  ) * 10;
}

/**
 * PEᵢ = IHᵢ × Dᵢ + Cᵢ
 * Eᵢ = min(10, (PEᵢ / TL) × 10)
 */
export function calculateEconomicImpact(
  input: EconomicImpactInput,
): EconomicImpactResult {
  validateNonNegative(input.hourlyIncome, 'hourlyIncome');
  validateNonNegative(input.interruptionHours, 'interruptionHours');
  validateNonNegative(input.recoveryCost, 'recoveryCost');

  if (
    !Number.isFinite(input.tolerableLoss) ||
    input.tolerableLoss <= 0
  ) {
    throw new RangeError(
      'tolerableLoss debe ser un número finito mayor que 0.',
    );
  }

  const potentialLoss =
    input.hourlyIncome * input.interruptionHours +
    input.recoveryCost;

  if (!Number.isFinite(potentialLoss)) {
    throw new RangeError(
      'La pérdida económica potencial excede el rango numérico permitido.',
    );
  }

  const impact = Math.min(
    10,
    (potentialLoss / input.tolerableLoss) * 10,
  );

  return {
    potentialLoss,
    impact,
  };
}

/**
 * Rᵢ = Lᵢ × (0.40 Tᵢ + 0.60 Eᵢ) / 10
 */
export function calculateFindingRisk(
  input: FindingRiskInput,
): number {
  validateRange(input.likelihood, 'likelihood', 0, 1);
  validateRange(input.technicalImpact, 'technicalImpact', 0, 10);
  validateRange(input.economicImpact, 'economicImpact', 0, 10);

  return (
    input.likelihood *
    (
      0.4 * input.technicalImpact +
      0.6 * input.economicImpact
    )
  ) / 10;
}

/**
 * RiskIndex = promedio de los riesgos normalizados.
 * CyberScore = 100 × (1 - RiskIndex)
 *
 * Una lista vacía se rechaza porque no permite calcular
 * el promedio definido en la metodología.
 */
export function calculateCyberScore(
  findingRisks: readonly number[],
): CyberScoreResult {
  if (findingRisks.length === 0) {
    throw new RangeError(
      'No se puede calcular CyberScore sin riesgos incluidos.',
    );
  }

  for (const risk of findingRisks) {
    validateRange(risk, 'findingRisk', 0, 1);
  }

  const riskIndex =
    findingRisks.reduce((total, risk) => total + risk, 0) /
    findingRisks.length;

  const score = 100 * (1 - riskIndex);

  return {
    score,
    riskIndex,
    formulaVersion: CYBERSCORE_FORMULA_VERSION,
  };
}

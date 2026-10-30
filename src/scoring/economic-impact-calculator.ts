export interface EconomicImpactInput {
    monthlyRevenue: number;
    operatingHours: number;
    currency: string;
    interruptionHours: number;
    remediationHours: number;
}

export interface EconomicImpactResult {
    hourlyIncome: number;
    tolerableLoss: number;
    recoveryCost: number;
    interruptionLoss: number;
    potentialLoss: number;
    impact: number;
    currency: string;
    estimated: boolean;
    assumptions: string[];
}

const OPERATING_DAYS_PER_MONTH = 22;

const SUPPORTED_CURRENCIES = new Set([
    'COP',
    'USD',
    'EUR',
    'MXN',
]);

export function calculateEconomicImpactForFinding(
    input: EconomicImpactInput,
): EconomicImpactResult {

    validateInput(input);

    // 1. Ingreso promedio por hora operativa.
    const hourlyIncome =
        input.monthlyRevenue / input.operatingHours;

    // 2. Pérdida tolerable estimada:
    // equivalente a un día promedio de ingresos.
    const tolerableLoss =
        input.monthlyRevenue / OPERATING_DAYS_PER_MONTH;

    // 3. Costo estimado de recuperación.
    const recoveryCost =
        hourlyIncome * input.remediationHours;

    // 4. Pérdida estimada por interrupción.
    const interruptionLoss =
        hourlyIncome * input.interruptionHours;

    // 5. Pérdida económica potencial.
    const potentialLoss =
        interruptionLoss + recoveryCost;

    if (
        !Number.isFinite(hourlyIncome) ||
        !Number.isFinite(tolerableLoss) ||
        !Number.isFinite(recoveryCost) ||
        !Number.isFinite(interruptionLoss) ||
        !Number.isFinite(potentialLoss)
    ) {
        throw new RangeError(
            'Los cálculos económicos exceden el rango numérico permitido.',
        );
    }

    // 6. Impacto económico CyberScore.
    const impact = Math.min(
        10,
        (potentialLoss / tolerableLoss) * 10,
    );

    return {
        hourlyIncome,
        tolerableLoss,
        recoveryCost,
        interruptionLoss,
        potentialLoss,
        impact,
        currency: input.currency.trim().toUpperCase(),
        estimated: true,

        assumptions: [
            'La pérdida tolerable equivale a un día promedio de ingresos.',
            'Se consideran 22 días operativos mensuales.',
            'El ingreso por hora se calcula utilizando las horas operativas declaradas por la PYME.',
            'El costo de recuperación se estima mediante las horas de remediación asignadas al hallazgo.',
            'Las horas de interrupción corresponden al perfil metodológico del hallazgo.',
            'Los resultados son estimaciones y no pérdidas económicas observadas.',
        ],
    };
}

function validateInput(input: EconomicImpactInput): void {
    if (!input || typeof input !== 'object') {
        throw new Error('Los datos económicos son obligatorios.');
    }

    if (
        !Number.isFinite(input.monthlyRevenue) ||
        input.monthlyRevenue <= 0
    ) {
        throw new RangeError(
            'Los ingresos mensuales deben ser mayores que cero.',
        );
    }

    if (
        !Number.isInteger(input.operatingHours) ||
        input.operatingHours < 1 ||
        input.operatingHours > 744
    ) {
        throw new RangeError(
            'Las horas operativas deben ser un entero entre 1 y 744.',
        );
    }

    if (
        typeof input.currency !== 'string' ||
        !SUPPORTED_CURRENCIES.has(input.currency.trim().toUpperCase())
    ) {
        throw new Error('La moneda de la PYME no es válida.');
    }

    validateNonNegative(
        input.interruptionHours,
        'Las horas de interrupción',
    );

    validateNonNegative(
        input.remediationHours,
        'Las horas de remediación',
    );
}

function validateNonNegative(
    value: number,
    description: string,
): void {
    if (!Number.isFinite(value) || value < 0) {
        throw new RangeError(
            `${description} deben ser un número finito no negativo.`,
        );
    }
}
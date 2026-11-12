
import {
    describe,
    expect,
    it,
} from '@jest/globals';

import {
    calculateEvaluationScore,
} from '../src/scoring/cyberscore-calculator';

import type {
    EvaluationScoreInput,
} from '../src/scoring/cyberscore-calculator';

describe('penalización VirusTotal en CyberScore', () => {
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
            findings: 0,
        },
    };

    function calculate(
        overrides: Partial<EvaluationScoreInput> = {},
    ) {
        return calculateEvaluationScore({
            findings: [],
            businessContext,
            layersSummary,
            ...overrides,
        });
    }

    it(
        'descuenta 25 puntos por cada detección maliciosa',
        () => {
            const result = calculate({
                virusTotal: {
                    status: 'completed',
                    stats: {
                        malicious: 2,
                        suspicious: 0,
                        harmless: 40,
                    },
                },
            });

            expect(result.baseScore).toBe(100);
            expect(result.virusTotalPenalty).toBe(50);
            expect(result.score).toBe(50);
        },
    );

    it(
        'descuenta 25 puntos por cada detección sospechosa',
        () => {
            const result = calculate({
                virusTotal: {
                    status: 'completed',
                    stats: {
                        malicious: 0,
                        suspicious: 3,
                        harmless: 20,
                    },
                },
            });

            expect(result.virusTotalPenalty).toBe(75);
            expect(result.score).toBe(25);
        },
    );

    it(
        'suma las detecciones maliciosas y sospechosas antes de calcular la penalización',
        () => {
            const result = calculate({
                virusTotal: {
                    status: 'completed',
                    stats: {
                        malicious: 2,
                        suspicious: 1,
                        harmless: 45,
                    },
                },
            });

            expect(result.virusTotalPenalty).toBe(75);
            expect(result.score).toBe(25);
        },
    );

    it(
        'no aplica penalización cuando no existen detecciones maliciosas ni sospechosas',
        () => {
            const result = calculate({
                virusTotal: {
                    status: 'completed',
                    stats: {
                        malicious: 0,
                        suspicious: 0,
                        harmless: 45,
                    },
                },
            });

            expect(result.virusTotalPenalty).toBe(0);
            expect(result.score).toBe(100);
        },
    );

    it(
        'no aplica penalización por motores que consideran el dominio inofensivo',
        () => {
            const result = calculate({
                virusTotal: {
                    status: 'completed',
                    stats: {
                        malicious: 0,
                        suspicious: 0,
                        harmless: 100,
                    },
                },
            });

            expect(result.virusTotalPenalty).toBe(0);
            expect(result.score).toBe(100);

            expect(result.virusTotalReputation).toBe(
                'Dominio Limpio (Confirmado por 100 motores de seguridad).',
            );
        },
    );

    it.each([
        'failed',
        'unavailable',
    ] as const)(
        'no aplica penalización cuando VirusTotal tiene estado %s',
        status => {
            const result = calculate({
                virusTotal: {
                    status,
                    stats: {
                        malicious: 5,
                        suspicious: 3,
                        harmless: 10,
                    },
                },
            });

            expect(result.virusTotalPenalty).toBe(0);
            expect(result.score).toBe(100);
            expect(result.virusTotalReputation).toBe(
                'Consulta no disponible',
            );
        },
    );

    it(
        'no aplica penalización cuando no se proporcionan datos de VirusTotal',
        () => {
            const result = calculate();

            expect(result.virusTotalPenalty).toBe(0);
            expect(result.score).toBe(100);
            expect(result.virusTotalReputation).toBe(
                'Consulta no disponible',
            );
        },
    );

    it(
        'genera una reputación crítica cuando existen alertas',
        () => {
            const result = calculate({
                virusTotal: {
                    status: 'completed',
                    stats: {
                        malicious: 2,
                        suspicious: 1,
                        harmless: 45,
                    },
                },
            });

            expect(result.virusTotalReputation).toBe(
                '¡ALERTA CRÍTICA! Marcado por 3 motores de seguridad.',
            );
        },
    );

    it(
        'combina las penalizaciones WHOIS y VirusTotal',
        () => {
            const result = calculate({
                whois: {
                    status: 'completed',
                    daysUntilExpiration: 10,
                },

                virusTotal: {
                    status: 'completed',
                    stats: {
                        malicious: 1,
                        suspicious: 1,
                        harmless: 30,
                    },
                },
            });

            expect(result.baseScore).toBe(100);

            expect(result.whoisPenalty).toBe(15);

            expect(result.virusTotalPenalty).toBe(50);

            expect(result.score).toBe(35);

            const scoring = result.layersSummary.scoring as Record<
                string,
                unknown
            >;

            expect(scoring).toMatchObject({
                whoisPenalty: 15,
                virusTotalPenalty: 50,
                totalPenalty: 65,
                virusTotalMalicious: 1,
                virusTotalSuspicious: 1,
                virusTotalTotalAlerts: 2,
            });
        },
    );

    it(
        'limita la puntuación final a cero cuando las penalizaciones superan la puntuación base',
        () => {
            const result = calculate({
                findings: [
                    {
                        layer: 'headers',
                        severity: 'medium',
                        title: 'Cabecera HSTS ausente',
                        description: 'Falta Strict-Transport-Security.',
                        evidence: null,
                    },
                ],

                virusTotal: {
                    status: 'completed',
                    stats: {
                        malicious: 10,
                        suspicious: 10,
                        harmless: 0,
                    },
                },
            });

            expect(result.virusTotalPenalty).toBe(500);
            expect(result.score).toBe(0);
            expect(result.rawScore).toBe(0);
            expect(result.riskIndex).toBe(1);
        },
    );

    it(
        'conserva las estadísticas de VirusTotal en el resumen de puntuación',
        () => {
            const result = calculate({
                virusTotal: {
                    status: 'completed',
                    stats: {
                        malicious: 2,
                        suspicious: 1,
                        harmless: 45,
                    },
                },
            });

            const scoring = result.layersSummary.scoring as Record<
                string,
                unknown
            >;

            expect(scoring).toMatchObject({
                virusTotalStatus: 'completed',
                virusTotalMalicious: 2,
                virusTotalSuspicious: 1,
                virusTotalHarmless: 45,
                virusTotalTotalAlerts: 3,
                virusTotalPenalty: 75,
            });
        },
    );

    it(
        'normaliza contadores negativos y decimales',
        () => {
            const result = calculate({
                virusTotal: {
                    status: 'completed',
                    stats: {
                        malicious: -2,
                        suspicious: 1.8,
                        harmless: 10.5,
                    },
                },
            });

            expect(result.virusTotalPenalty).toBe(25);

            const scoring = result.layersSummary.scoring as Record<
                string,
                unknown
            >;

            expect(scoring).toMatchObject({
                virusTotalMalicious: 0,
                virusTotalSuspicious: 1,
                virusTotalHarmless: 10,
            });
        },
    );

    it(
        'trata contadores no finitos como cero',
        () => {
            const result = calculate({
                virusTotal: {
                    status: 'completed',
                    stats: {
                        malicious: Number.NaN,
                        suspicious: Number.POSITIVE_INFINITY,
                        harmless: 10,
                    },
                },
            });

            expect(result.virusTotalPenalty).toBe(0);

            const scoring = result.layersSummary.scoring as Record<
                string,
                unknown
            >;

            expect(scoring).toMatchObject({
                virusTotalMalicious: 0,
                virusTotalSuspicious: 0,
                virusTotalHarmless: 10,
            });
        },
    );
});

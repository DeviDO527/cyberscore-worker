import { describe, expect, it } from '@jest/globals';

import {
    calculateEvaluationScore,
    type EvaluationScoreInput,
    type NmapScoringPort,
} from '../src/scoring/cyberscore-calculator';

describe('penalización Nmap en CyberScore', () => {
    const businessContext = {
        monthlyRevenue: 30_000_000,
        operatingHours: 300,
        currency: 'COP',
    };

    const layersSummary = {
        dns: { status: 'completed', findings: 0 },
        tls: { status: 'completed', findings: 0 },
        headers: { status: 'completed', findings: 0 },
    };

    const port = (
        number: number,
        serviceDetails = 'SERVICE',
        state = 'open',
    ): NmapScoringPort => ({
        port: number,
        protocol: 'TCP',
        state,
        serviceDetails,
    });

    const calculate = (
        overrides: Partial<EvaluationScoreInput> = {},
    ) => calculateEvaluationScore({
        findings: [],
        businessContext,
        layersSummary,
        ...overrides,
    });

    it.each([21, 22, 23, 3306, 3389])(
        'descuenta 20 puntos por el puerto sensible %i',
        sensitivePort => {
            const result = calculate({
                nmap: {
                    status: 'completed',
                    openPorts: [port(sensitivePort)],
                },
            });

            expect(result.baseScore).toBe(100);
            expect(result.nmapPenalty).toBe(20);
            expect(result.score).toBe(80);
            expect(result.nmapPenaltyBreakdown).toEqual({
                sensitivePortCount: 1,
                sensitivePenalty: 20,
                nonStandardPortCount: 0,
                nonStandardPenalty: 0,
            });
        },
    );

    it('descuenta 10 puntos por cada puerto abierto no estándar', () => {
        const result = calculate({
            nmap: {
                status: 'completed',
                openPorts: [port(8080), port(8443)],
            },
        });

        expect(result.nmapPenalty).toBe(20);
        expect(result.score).toBe(80);
        expect(result.nmapPenaltyBreakdown).toMatchObject({
            nonStandardPortCount: 2,
            nonStandardPenalty: 20,
        });
    });

    it('no descuenta los puertos web 80 y 443', () => {
        const result = calculate({
            nmap: {
                status: 'completed',
                openPorts: [port(80), port(443)],
            },
        });

        expect(result.nmapPenalty).toBe(0);
        expect(result.score).toBe(100);
        expect(result.nmapPenaltyBreakdown).toEqual({
            sensitivePortCount: 0,
            sensitivePenalty: 0,
            nonStandardPortCount: 0,
            nonStandardPenalty: 0,
        });
    });

    it.each(['skipped', 'failed', 'not_provided'])(
        'no aplica penalización si el escaneo tiene estado %s',
        status => {
            const result = calculate({
                nmap: {
                    status,
                    openPorts: [port(22), port(8080)],
                },
            });

            expect(result.nmapPenalty).toBe(0);
            expect(result.score).toBe(100);
        },
    );

    it('no penaliza puertos que no están abiertos', () => {
        const result = calculate({
            nmap: {
                status: 'completed',
                openPorts: [
                    port(22, 'SSH', 'closed'),
                    port(8080, 'HTTP-PROXY', 'filtered'),
                ],
            },
        });

        expect(result.nmapPenalty).toBe(0);
        expect(result.nmapPenaltyBreakdown.sensitivePortCount).toBe(0);
        expect(result.nmapPenaltyBreakdown.nonStandardPortCount).toBe(0);
    });

    it('suma las penalizaciones de Nmap, WHOIS y VirusTotal', () => {
        const result = calculate({
            nmap: {
                status: 'completed',
                openPorts: [port(22), port(8080)],
            },
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

        expect(result.nmapPenalty).toBe(30);
        expect(result.whoisPenalty).toBe(15);
        expect(result.virusTotalPenalty).toBe(50);
        expect(result.layersSummary.scoring).toMatchObject({
            nmapPenalty: 30,
            nmapStatus: 'completed',
            nmapPenaltyBreakdown: {
                sensitivePortCount: 1,
                sensitivePenalty: 20,
                nonStandardPortCount: 1,
                nonStandardPenalty: 10,
            },
            totalPenalty: 95,
        });
        expect(result.score).toBe(5);
    });

    it('mantiene la puntuación final en cero cuando las penalizaciones exceden la base', () => {
        const result = calculate({
            nmap: {
                status: 'completed',
                openPorts: [
                    port(21),
                    port(22),
                    port(23),
                    port(3306),
                    port(3389),
                    port(8080),
                ],
            },
        });

        expect(result.nmapPenalty).toBe(110);
        expect(result.score).toBe(0);
        expect(result.rawScore).toBe(0);
    });

    it('registra la versión de fórmula que incorpora la penalización Nmap', () => {
        const result = calculate({
            nmap: {
                status: 'completed',
                openPorts: [port(22)],
            },
        });

        expect(result.formulaVersion).toBe('1.1');
        expect(result.layersSummary.scoring).toMatchObject({
            formulaVersion: '1.1',
            assumptions: expect.arrayContaining([
                expect.stringContaining('Nmap descuenta 20 puntos'),
                expect.stringContaining('no demuestra por sí misma una vulnerabilidad'),
            ]),
        });
    });

    it('rechaza puertos abiertos con datos incompletos', () => {
        expect(() => calculate({
            nmap: {
                status: 'completed',
                openPorts: [{
                    port: 22,
                    protocol: '',
                    state: 'open',
                    serviceDetails: 'SSH',
                }],
            },
        })).toThrow('no contiene datos válidos');
    });
});

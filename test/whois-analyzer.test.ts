
import {
    describe,
    expect,
    it,
} from '@jest/globals';

import {
    RdapInspector,
} from '../src/services/rdap-inspector';

import {
    WhoisAnalyzer,
} from '../src/security/whois-analyzer';

interface RdapInspectionResult {
    domain: string;
    statuses: string[];
    creationDate: string | null;
    expirationDate: string | null;
    updatedDate: string | null;
    registrar: string | null;
}

describe('WhoisAnalyzer', () => {
    function createRdapInspectorMock(
        result: RdapInspectionResult,
    ): RdapInspector {
        return {
            inspect: async () => result,
        } as unknown as RdapInspector;
    }

    function createAnalyzer(
        rdapResult: RdapInspectionResult,
        now: Date,
    ): WhoisAnalyzer {
        return new WhoisAnalyzer({
            rdapInspector:
                createRdapInspectorMock(rdapResult),
            now: () => now,
        });
    }

    function createRdapResult(
        overrides: Partial<RdapInspectionResult> = {},
    ): RdapInspectionResult {
        return {
            domain: 'example.com',
            statuses: ['active'],
            creationDate: '2020-01-01T00:00:00Z',
            expirationDate: '2027-01-01T00:00:00Z',
            updatedDate: null,
            registrar: 'Example Registrar',
            ...overrides,
        };
    }

    it(
        'calcula la antigüedad y los días restantes para el vencimiento',
        async () => {
            const analyzer = createAnalyzer(
                createRdapResult({
                    creationDate: '2025-01-01T00:00:00Z',
                    expirationDate: '2027-01-01T00:00:00Z',
                }),
                new Date('2026-01-01T00:00:00Z'),
            );

            const result =
                await analyzer.analyze('example.com');

            expect(result.status).toBe('completed');
            expect(result.domainAgeDays).toBe(365);
            expect(result.daysUntilExpiration).toBe(365);
            expect(result.findings).toEqual([]);
            expect(result.error).toBeNull();
        },
    );

    it(
        'genera un hallazgo cuando quedan 29 días para vencer',
        async () => {
            const analyzer = createAnalyzer(
                createRdapResult({
                    expirationDate: '2026-03-02T00:00:00Z',
                }),
                new Date('2026-02-01T00:00:00Z'),
            );

            const result =
                await analyzer.analyze('example.com');

            expect(result.daysUntilExpiration).toBe(29);

            expect(result.findings).toEqual([
                {
                    title: 'Dominio próximo a vencer',
                    severity: 'medium',
                    description:
                        'Dominio próximo a vencer en WHOIS (29 días restantes).',
                },
            ]);
        },
    );

    it(
        'genera un hallazgo cuando queda un día para vencer',
        async () => {
            const analyzer = createAnalyzer(
                createRdapResult({
                    expirationDate: '2026-02-02T00:00:00Z',
                }),
                new Date('2026-02-01T00:00:00Z'),
            );

            const result =
                await analyzer.analyze('example.com');

            expect(result.daysUntilExpiration).toBe(1);
            expect(result.findings).toHaveLength(1);
        },
    );

    it(
        'no genera hallazgo cuando quedan exactamente 30 días',
        async () => {
            const analyzer = createAnalyzer(
                createRdapResult({
                    expirationDate: '2026-03-03T00:00:00Z',
                }),
                new Date('2026-02-01T00:00:00Z'),
            );

            const result =
                await analyzer.analyze('example.com');

            expect(result.daysUntilExpiration).toBe(30);
            expect(result.findings).toEqual([]);
        },
    );

    it(
        'no genera hallazgo cuando el dominio vence hoy',
        async () => {
            const analyzer = createAnalyzer(
                createRdapResult({
                    expirationDate: '2026-02-01T00:00:00Z',
                }),
                new Date('2026-02-01T00:00:00Z'),
            );

            const result =
                await analyzer.analyze('example.com');

            expect(result.daysUntilExpiration).toBe(0);
            expect(result.findings).toEqual([]);
        },
    );

    it(
        'no genera hallazgo cuando el dominio ya venció',
        async () => {
            const analyzer = createAnalyzer(
                createRdapResult({
                    expirationDate: '2026-01-01T00:00:00Z',
                }),
                new Date('2026-02-01T00:00:00Z'),
            );

            const result =
                await analyzer.analyze('example.com');

            expect(result.daysUntilExpiration).toBeLessThan(0);
            expect(result.findings).toEqual([]);
        },
    );

    it(
        'no genera hallazgo por tener menos de 30 días de antigüedad',
        async () => {
            const analyzer = createAnalyzer(
                createRdapResult({
                    creationDate: '2026-01-15T00:00:00Z',
                    expirationDate: '2027-01-15T00:00:00Z',
                }),
                new Date('2026-02-01T00:00:00Z'),
            );

            const result =
                await analyzer.analyze('example.com');

            expect(result.domainAgeDays).toBe(17);
            expect(result.findings).toEqual([]);
        },
    );

    it(
        'utiliza cero cuando RDAP no proporciona las fechas',
        async () => {
            const analyzer = createAnalyzer(
                createRdapResult({
                    creationDate: null,
                    expirationDate: null,
                }),
                new Date('2026-02-01T00:00:00Z'),
            );

            const result =
                await analyzer.analyze('example.com');

            expect(result.domainAgeDays).toBe(0);
            expect(result.daysUntilExpiration).toBe(0);
            expect(result.findings).toEqual([]);
        },
    );

    it(
        'conserva los datos del registrador y las fechas',
        async () => {
            const analyzer = createAnalyzer(
                createRdapResult(),
                new Date('2026-02-01T00:00:00Z'),
            );

            const result =
                await analyzer.analyze('example.com');

            expect(result.creationDate).toBe(
                '2020-01-01T00:00:00Z',
            );

            expect(result.expirationDate).toBe(
                '2027-01-01T00:00:00Z',
            );

            expect(result.registrar).toBe(
                'Example Registrar',
            );
        },
    );

    it(
        'devuelve un resultado fallido cuando RDAP genera un error',
        async () => {
            const rdapInspector = {
                inspect: async () => {
                    throw new Error('Servicio RDAP no disponible');
                },
            } as unknown as RdapInspector;

            const analyzer = new WhoisAnalyzer({
                rdapInspector,
                now: () => new Date('2026-02-01T00:00:00Z'),
            });

            const result =
                await analyzer.analyze('example.com');

            expect(result.status).toBe('failed');
            expect(result.domain).toBe('example.com');
            expect(result.domainAgeDays).toBe(0);
            expect(result.daysUntilExpiration).toBe(0);
            expect(result.findings).toEqual([]);

            expect(result.error).toBe(
                'No se pudo consultar WHOIS: Servicio RDAP no disponible',
            );
        },
    );

    it('usa cero cuando RDAP devuelve una fecha de creación inválida', async () => {
        const analyzer = createAnalyzer(
            createRdapResult({ creationDate: 'no-es-una-fecha' }),
            new Date('2026-02-01T00:00:00Z'),
        );

        const result = await analyzer.analyze('example.com');

        expect(result.status).toBe('completed');
        expect(result.creationDate).toBe('no-es-una-fecha');
        expect(result.domainAgeDays).toBe(0);
    });

    it('usa la fecha actual cuando no se inyecta un reloj', async () => {
        const analyzer = new WhoisAnalyzer({
            rdapInspector: createRdapInspectorMock(createRdapResult()),
        });

        const result = await analyzer.analyze('example.com');

        expect(result.status).toBe('completed');
        expect(result.error).toBeNull();
    });

    it('formatea rechazos de RDAP que no son instancias de Error', async () => {
        const rdapInspector = {
            inspect: () => Promise.reject('respuesta inválida'),
        } as unknown as RdapInspector;
        const analyzer = new WhoisAnalyzer({ rdapInspector });

        const result = await analyzer.analyze('example.com');

        expect(result.status).toBe('failed');
        expect(result.error).toBe(
            'No se pudo consultar WHOIS: respuesta inválida',
        );
    });
});

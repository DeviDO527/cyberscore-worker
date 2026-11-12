import {
    describe,
    it,
    expect,
} from '@jest/globals';

import {
    FINDING_RISK_MATRIX,
    resolveFindingRiskProfile,
} from '../src/scoring/finding-risk-matrix';

describe('FindingRiskMatrix', () => {

    const findings = [
        {
            layer: 'tls',
            title: 'Certificado TLS no autorizado',
            description: 'No se pudo validar la confianza del certificado TLS.',
            profile: 'TLS_CERTIFICATE_UNAUTHORIZED',
        },
        {
            layer: 'headers',
            title: 'Cabecera de seguridad ausente',
            description: 'No se encontró Strict-Transport-Security (HSTS).',
            profile: 'HTTP_HSTS_MISSING',
        },
        {
            layer: 'headers',
            title: 'Cabecera de seguridad ausente',
            description: 'No se encontró Content-Security-Policy (CSP).',
            profile: 'HTTP_CSP_MISSING',
        },
        {
            layer: 'headers',
            title: 'Cabecera de seguridad ausente',
            description: 'No se encontró X-Content-Type-Options.',
            profile: 'HTTP_X_CONTENT_TYPE_OPTIONS_MISSING',
        },
        {
            layer: 'headers',
            title: 'Cabecera de seguridad ausente',
            description: 'No se encontró X-Frame-Options.',
            profile: 'HTTP_X_FRAME_OPTIONS_MISSING',
        },
        {
            layer: 'headers',
            title: 'Cabecera de seguridad ausente',
            description: 'No se encontró Referrer-Policy.',
            profile: 'HTTP_REFERRER_POLICY_MISSING',
        },
        {
            layer: 'headers',
            title: 'Cabecera de seguridad ausente',
            description: 'No se encontró X-XSS-Protection.',
            profile: 'HTTP_X_XSS_PROTECTION_MISSING',
        },
    ];

    it('contiene un perfil para cada uno de los hallazgos de cabeceras y TLS', () => {
        expect(FINDING_RISK_MATRIX).toHaveLength(7);
    });

    it.each(findings)(
        'identifica correctamente el perfil $profile',
        ({ layer, title, description, profile }) => {

            const result = resolveFindingRiskProfile({
                layer,
                title,
                description,
            });

            expect(result.id).toBe(profile);
        },
    );

    it('mantiene los factores de probabilidad dentro del intervalo 0-9', () => {
        for (const profile of FINDING_RISK_MATRIX) {
            expect(profile.likelihood.discovery).toBeGreaterThanOrEqual(0);
            expect(profile.likelihood.discovery).toBeLessThanOrEqual(9);

            expect(profile.likelihood.exploitation).toBeGreaterThanOrEqual(0);
            expect(profile.likelihood.exploitation).toBeLessThanOrEqual(9);

            expect(profile.likelihood.awareness).toBeGreaterThanOrEqual(0);
            expect(profile.likelihood.awareness).toBeLessThanOrEqual(9);

            expect(profile.likelihood.detectionDifficulty).toBeGreaterThanOrEqual(0);
            expect(profile.likelihood.detectionDifficulty).toBeLessThanOrEqual(9);
        }
    });

    it('mantiene los factores de impacto técnico dentro del intervalo 0-9', () => {
        for (const profile of FINDING_RISK_MATRIX) {
            const factors = profile.technicalImpact;

            expect(factors.confidentiality).toBeGreaterThanOrEqual(0);
            expect(factors.confidentiality).toBeLessThanOrEqual(9);

            expect(factors.integrity).toBeGreaterThanOrEqual(0);
            expect(factors.integrity).toBeLessThanOrEqual(9);

            expect(factors.availability).toBeGreaterThanOrEqual(0);
            expect(factors.availability).toBeLessThanOrEqual(9);

            expect(factors.accountability).toBeGreaterThanOrEqual(0);
            expect(factors.accountability).toBeLessThanOrEqual(9);
        }
    });

    it('rechaza hallazgos sin un perfil metodológico definido', () => {
        expect(() =>
            resolveFindingRiskProfile({
                layer: 'dns',
                title: 'Hallazgo desconocido',
                description: 'Un problema no contemplado en la matriz.',
            }),
        ).toThrow('No existe un perfil metodológico');
    });

    it('define explícitamente las horas de interrupción y remediación', () => {
        for (const profile of FINDING_RISK_MATRIX) {
            expect(profile.interruptionHours).toBe(0);
            expect(profile.remediationHours).toBeGreaterThan(0);
        }
    });
});

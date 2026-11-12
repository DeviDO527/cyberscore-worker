export const FINDING_RISK_MATRIX_VERSION = '1.1';

export interface LikelihoodFactors {
    discovery: number;
    exploitation: number;
    awareness: number;
    detectionDifficulty: number;
}

export interface TechnicalImpactFactors {
    confidentiality: number;
    integrity: number;
    availability: number;
    accountability: number;
}

export interface FindingRiskProfile {
    id: string;
    layer: 'tls' | 'headers';

    matchTerms: string[];

    likelihood: LikelihoodFactors;

    technicalImpact: TechnicalImpactFactors;

    interruptionHours: number;

    remediationHours: number;

    assumptions: string[];
}

export interface FindingIdentification {
    layer: string;
    title: string;
    description: string;
}

/**
 * Matriz metodológica CyberScore PYME v1.1.
 *
 * Los valores constituyen estimaciones propias del proyecto,
 * fundamentadas en criterios de OWASP Risk Rating Methodology.
 *
 * No representan mediciones directas de las condiciones
 * internas de seguridad de la PYME.
 */
export const FINDING_RISK_MATRIX: readonly FindingRiskProfile[] = [

    // =====================================================
    // TLS
    // =====================================================

    {
        id: 'TLS_CERTIFICATE_UNAUTHORIZED',

        layer: 'tls',

        matchTerms: [
            'certificado tls no autorizado',
        ],

        likelihood: {
            discovery: 9,
            exploitation: 5,
            awareness: 9,
            detectionDifficulty: 8,
        },

        technicalImpact: {
            confidentiality: 6,
            integrity: 6,
            availability: 0,
            accountability: 0,
        },

        interruptionHours: 0,

        remediationHours: 2,

        assumptions: [
            'El certificado no supera la validación de confianza.',
            'La explotación depende de condiciones adicionales.',
            'No se demuestra por sí sola una interceptación de comunicaciones.',
            'El factor de detección interna utiliza un supuesto provisional.',
        ],
    },

    // =====================================================
    // HTTP HEADERS
    // =====================================================

    {
        id: 'HTTP_HSTS_MISSING',

        layer: 'headers',

        matchTerms: [
            'strict-transport-security',
            'hsts',
        ],

        likelihood: {
            discovery: 9,
            exploitation: 3,
            awareness: 9,
            detectionDifficulty: 8,
        },

        technicalImpact: {
            confidentiality: 2,
            integrity: 2,
            availability: 0,
            accountability: 0,
        },

        interruptionHours: 0,

        remediationHours: 0.5,

        assumptions: [
            'La ausencia de HSTS es observable externamente.',
            'La explotación depende de condiciones de transporte adicionales.',
            'La ausencia de la cabecera no demuestra una degradación exitosa.',
            'El factor de detección interna utiliza un supuesto provisional.',
        ],
    },

    {
        id: 'HTTP_CSP_MISSING',

        layer: 'headers',

        matchTerms: [
            'content-security-policy',
            'csp',
        ],

        likelihood: {
            discovery: 9,
            exploitation: 3,
            awareness: 9,
            detectionDifficulty: 8,
        },

        technicalImpact: {
            confidentiality: 2,
            integrity: 3,
            availability: 0,
            accountability: 0,
        },

        interruptionHours: 0,

        remediationHours: 2,

        assumptions: [
            'La ausencia de CSP es observable externamente.',
            'La explotación depende de vulnerabilidades adicionales de inyección.',
            'No se presupone la existencia de XSS.',
            'El factor de detección interna utiliza un supuesto provisional.',
        ],
    },

    {
        id: 'HTTP_X_CONTENT_TYPE_OPTIONS_MISSING',

        layer: 'headers',

        matchTerms: [
            'x-content-type-options',
        ],

        likelihood: {
            discovery: 9,
            exploitation: 3,
            awareness: 9,
            detectionDifficulty: 8,
        },

        technicalImpact: {
            confidentiality: 1,
            integrity: 2,
            availability: 0,
            accountability: 0,
        },

        interruptionHours: 0,

        remediationHours: 0.5,

        assumptions: [
            'La ausencia de la cabecera es observable externamente.',
            'La explotación depende del comportamiento del navegador y del contenido servido.',
            'No se presupone una vulnerabilidad explotable.',
            'El factor de detección interna utiliza un supuesto provisional.',
        ],
    },

    {
        id: 'HTTP_X_FRAME_OPTIONS_MISSING',

        layer: 'headers',

        matchTerms: [
            'x-frame-options',
        ],

        likelihood: {
            discovery: 9,
            exploitation: 3,
            awareness: 9,
            detectionDifficulty: 8,
        },

        technicalImpact: {
            confidentiality: 1,
            integrity: 2,
            availability: 0,
            accountability: 0,
        },

        interruptionHours: 0,

        remediationHours: 0.5,

        assumptions: [
            'La ausencia de la cabecera es observable externamente.',
            'La explotación depende de que existan funcionalidades vulnerables a clickjacking.',
            'No se presupone una interfaz explotable.',
            'El factor de detección interna utiliza un supuesto provisional.',
        ],
    },

    {
        id: 'HTTP_REFERRER_POLICY_MISSING',

        layer: 'headers',

        matchTerms: [
            'referrer-policy',
        ],

        likelihood: {
            discovery: 9,
            exploitation: 3,
            awareness: 9,
            detectionDifficulty: 8,
        },

        technicalImpact: {
            confidentiality: 2,
            integrity: 0,
            availability: 0,
            accountability: 0,
        },

        interruptionHours: 0,

        remediationHours: 0.25,

        assumptions: [
            'La ausencia de la cabecera es observable externamente.',
            'La exposición depende de las URL y de la información contenida en ellas.',
            'No se presupone filtración efectiva de credenciales.',
            'El factor de detección interna utiliza un supuesto provisional.',
        ],
    },

    {
        id: 'HTTP_X_XSS_PROTECTION_MISSING',

        layer: 'headers',

        matchTerms: [
            'x-xss-protection',
        ],

        likelihood: {
            discovery: 9,
            exploitation: 2,
            awareness: 9,
            detectionDifficulty: 8,
        },

        technicalImpact: {
            confidentiality: 1,
            integrity: 2,
            availability: 0,
            accountability: 0,
        },

        interruptionHours: 0,

        remediationHours: 0.25,

        assumptions: [
            'La ausencia de la cabecera es observable externamente.',
            'X-XSS-Protection es una cabecera heredada y su efecto depende del navegador.',
            'No se presupone que exista una vulnerabilidad XSS ni que esta cabecera la evite.',
            'El factor de detección interna utiliza un supuesto provisional.',
        ],
    },
] as const;

/**
 * Identifica el perfil metodológico asociado a un hallazgo.
 *
 * Utiliza la capa, el título y la descripción.
 * No asigna factores a hallazgos desconocidos.
 */
export function resolveFindingRiskProfile(
    finding: FindingIdentification,
): FindingRiskProfile {

    const normalizedLayer = finding.layer
        .trim()
        .toLowerCase();

    const searchableText = `${finding.title} ${finding.description}`
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .toLowerCase();

    const profile = FINDING_RISK_MATRIX.find((candidate) => {

        if (candidate.layer !== normalizedLayer) {
            return false;
        }

        return candidate.matchTerms.some((term) => {
            const normalizedTerm = term
                .normalize('NFD')
                .replace(/[\u0300-\u036f]/g, '')
                .toLowerCase();

            return searchableText.includes(normalizedTerm);
        });
    });

    if (!profile) {
        throw new Error(
            `No existe un perfil metodológico para el hallazgo: ${finding.layer}/${finding.title}`,
        );
    }

    return profile;
}

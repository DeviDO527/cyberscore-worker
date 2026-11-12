import {
    afterEach,
    beforeEach,
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';

import { TlsAnalyzer } from '../src/security/tls-analyzer';

describe('TlsAnalyzer', () => {
    let tlsMock: {
        inspect: ReturnType<typeof jest.fn>;
    };

    let analyzer: TlsAnalyzer;

    beforeEach(() => {
        jest.clearAllMocks();

        tlsMock = {
            inspect: jest.fn(),
        };

        analyzer = new TlsAnalyzer(tlsMock);
    });

    afterEach(() => {
        jest.useRealTimers();
    });

    it('consulta la información TLS del dominio', async () => {
        tlsMock.inspect.mockResolvedValue({
            authorized: true,
            protocol: 'TLSv1.3',
            validFrom: 'Jan 01 00:00:00 2026 GMT',
            validTo: 'Jan 01 00:00:00 2027 GMT',
            subject: { CN: 'example.com' },
            issuer: { CN: 'Example CA' },
        });

        await analyzer.analyze('example.com');

        expect(tlsMock.inspect).toHaveBeenCalledWith('example.com');
    });

    it('devuelve la información del certificado incluyendo los días restantes', async () => {
        jest.useFakeTimers();
        jest.setSystemTime(
            new Date('2026-01-01T00:00:00.000Z'),
        );

        tlsMock.inspect.mockResolvedValue({
            authorized: true,
            protocol: 'TLSv1.3',
            validFrom: 'Jan 01 00:00:00 2026 GMT',
            validTo: 'Jan 31 00:00:00 2026 GMT',
            subject: { CN: 'example.com' },
            issuer: { CN: 'Example CA' },
        });

        const result = await analyzer.analyze('example.com');

        expect(result).toEqual({
            status: 'completed',
            authorized: true,
            protocol: 'TLSv1.3',
            certificate: {
                validFrom: 'Jan 01 00:00:00 2026 GMT',
                validTo: 'Jan 31 00:00:00 2026 GMT',
                daysRemaining: 30,
                subject: { CN: 'example.com' },
                issuer: { CN: 'Example CA' },
            },
            findings: [],
        });
    });

    it('calcula un valor negativo cuando el certificado ya venció', async () => {
        jest.useFakeTimers();
        jest.setSystemTime(
            new Date('2026-02-01T00:00:00.000Z'),
        );

        tlsMock.inspect.mockResolvedValue({
            authorized: true,
            protocol: 'TLSv1.3',
            validFrom: 'Jan 01 00:00:00 2025 GMT',
            validTo: 'Jan 22 00:00:00 2026 GMT',
            subject: { CN: 'example.com' },
            issuer: { CN: 'Example CA' },
        });

        const result = await analyzer.analyze('example.com');

        expect(result.certificate.daysRemaining).toBe(-10);
    });

    it('devuelve null cuando la fecha de vencimiento no es válida', async () => {
        tlsMock.inspect.mockResolvedValue({
            authorized: true,
            protocol: 'TLSv1.3',
            validFrom: 'Jan 01 00:00:00 2026 GMT',
            validTo: 'fecha inválida',
            subject: { CN: 'example.com' },
            issuer: { CN: 'Example CA' },
        });

        const result = await analyzer.analyze('example.com');

        expect(result.certificate.daysRemaining).toBeNull();
    });

    it('genera un hallazgo cuando el certificado no está autorizado', async () => {
        tlsMock.inspect.mockResolvedValue({
            authorized: false,
            authorizationError: 'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
            protocol: 'TLSv1.2',
            validFrom: 'Jan 01 00:00:00 2026 GMT',
            validTo: 'Jan 01 00:00:00 2027 GMT',
            subject: { CN: 'example.com' },
            issuer: { CN: 'Unknown CA' },
        });

        const result = await analyzer.analyze('example.com');

        expect(result.findings).toEqual([
            expect.objectContaining({
                severity: 'high',
            }),
        ]);
    });

    it('indica que la causa no fue especificada si falta el error de autorización', async () => {
        tlsMock.inspect.mockResolvedValue({
            authorized: false,
            protocol: 'TLSv1.2',
            validFrom: 'Jan 01 00:00:00 2026 GMT',
            validTo: 'Jan 01 00:00:00 2027 GMT',
            subject: { CN: 'example.com' },
            issuer: { CN: 'Unknown CA' },
        });

        const result = await analyzer.analyze('example.com');

        expect(result.findings).toEqual([
            expect.objectContaining({
                description: expect.stringContaining(
                    'La causa no fue especificada.',
                ),
            }),
        ]);
    });

    it('rechaza un dominio vacío sin consultar TLS', async () => {
        await expect(analyzer.analyze('')).rejects.toThrow();

        expect(tlsMock.inspect).not.toHaveBeenCalled();
    });

    it('rechaza una entrada con formato de dominio inválido', async () => {
        await expect(
            analyzer.analyze('esto no es un dominio'),
        ).rejects.toThrow();

        expect(tlsMock.inspect).not.toHaveBeenCalled();
    });

    it('propaga los errores inesperados de la inspección TLS', async () => {
        tlsMock.inspect.mockRejectedValue(
            new Error('No fue posible establecer la conexión TLS'),
        );

        await expect(
            analyzer.analyze('example.com'),
        ).rejects.toThrow(
            'No fue posible establecer la conexión TLS',
        );
    });
});
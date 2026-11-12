import { jest, describe, it, expect, beforeEach } from '@jest/globals';

import { DnsAnalyzer } from '../src/security/dns-analyzer';

describe('DnsAnalyzer', () => {
    let dnsMock: {
        resolve4: ReturnType<typeof jest.fn>;
        resolve6: ReturnType<typeof jest.fn>;
        resolveMx: ReturnType<typeof jest.fn>;
        resolveNs: ReturnType<typeof jest.fn>;
    };

    let analyzer: DnsAnalyzer;

    beforeEach(() => {
        jest.clearAllMocks();

        dnsMock = {
            resolve4: jest.fn(),
            resolve6: jest.fn(),
            resolveMx: jest.fn(),
            resolveNs: jest.fn(),
        };

        analyzer = new DnsAnalyzer(dnsMock);
    });

    it('consulta los registros A, AAAA, MX y NS', async () => {
        dnsMock.resolve4.mockResolvedValue(['203.0.113.10']);
        dnsMock.resolve6.mockResolvedValue(['2001:db8::10']);
        dnsMock.resolveMx.mockResolvedValue([
            { exchange: 'mail.example.com', priority: 10 },
        ]);
        dnsMock.resolveNs.mockResolvedValue(['ns1.example.com']);

        await analyzer.analyze('example.com');

        expect(dnsMock.resolve4).toHaveBeenCalledWith('example.com');
        expect(dnsMock.resolve6).toHaveBeenCalledWith('example.com');
        expect(dnsMock.resolveMx).toHaveBeenCalledWith('example.com');
        expect(dnsMock.resolveNs).toHaveBeenCalledWith('example.com');
    });

    it('devuelve los registros DNS recopilados', async () => {
        dnsMock.resolve4.mockResolvedValue(['203.0.113.10']);
        dnsMock.resolve6.mockResolvedValue(['2001:db8::10']);
        dnsMock.resolveMx.mockResolvedValue([]);
        dnsMock.resolveNs.mockResolvedValue(['ns1.example.com']);

        const result = await analyzer.analyze('example.com');

        expect(result.records).toEqual({
            a: ['203.0.113.10'],
            aaaa: ['2001:db8::10'],
            mx: [],
            ns: ['ns1.example.com'],
        });

        expect(result.status).toBe('completed');
        
        expect(result.findings).toEqual([]);

    });

    it('rechaza un dominio vacío', async () => {
        await expect(analyzer.analyze('')).rejects.toThrow();

        expect(dnsMock.resolve4).not.toHaveBeenCalled();
        expect(dnsMock.resolve6).not.toHaveBeenCalled();
        expect(dnsMock.resolveMx).not.toHaveBeenCalled();
        expect(dnsMock.resolveNs).not.toHaveBeenCalled();
    });

    it('rechaza un dominio con formato inválido', async () => {
        await expect(
            analyzer.analyze('esto no es un dominio'),
        ).rejects.toThrow();

        expect(dnsMock.resolve4).not.toHaveBeenCalled();
    });

    it('distingue una respuesta DNS vacía de un error de consulta', async () => {
        dnsMock.resolve4.mockResolvedValue([]);
        dnsMock.resolve6.mockResolvedValue([]);
        dnsMock.resolveMx.mockResolvedValue([]);
        dnsMock.resolveNs.mockResolvedValue([]);

        const result = await analyzer.analyze('example.com');

        expect(result.records).toEqual({
            a: [],
            aaaa: [],
            mx: [],
            ns: [],
        });
    });

    it('propaga los errores inesperados de consulta DNS', async () => {
        dnsMock.resolve4.mockRejectedValue(
            new Error('Error de resolución DNS'),
        );
        dnsMock.resolve6.mockResolvedValue([]);
        dnsMock.resolveMx.mockResolvedValue([]);
        dnsMock.resolveNs.mockResolvedValue([]);

        await expect(
            analyzer.analyze('example.com'),
        ).rejects.toThrow('Error de resolución DNS');
    });

    it('trata ENODATA como una consulta sin registros', async () => {
        dnsMock.resolve4.mockRejectedValue(
            Object.assign(new Error('No hay registros A'), { code: 'ENODATA' }),
        );
        dnsMock.resolve6.mockResolvedValue([]);
        dnsMock.resolveMx.mockResolvedValue([]);
        dnsMock.resolveNs.mockResolvedValue([]);

        const result = await analyzer.analyze('example.com');

        expect(result.records.a).toEqual([]);
        expect(result.status).toBe('completed');
    });
});

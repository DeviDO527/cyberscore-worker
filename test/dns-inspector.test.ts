import { beforeEach, describe, expect, it, jest } from '@jest/globals';

import { DnsInspector } from '../src/services/dns-inspector';

describe('DnsInspector', () => {
    let resolverMock: {
        resolve4: ReturnType<typeof jest.fn>;
        resolve6: ReturnType<typeof jest.fn>;
        resolveMx: ReturnType<typeof jest.fn>;
        resolveNs: ReturnType<typeof jest.fn>;
    };

    let inspector: DnsInspector;

    beforeEach(() => {
        jest.clearAllMocks();

        resolverMock = {
            resolve4: jest.fn(),
            resolve6: jest.fn(),
            resolveMx: jest.fn(),
            resolveNs: jest.fn(),
        };

        inspector = new DnsInspector(resolverMock);
    });

    it('consulta los registros A, AAAA, MX y NS', async () => {
        resolverMock.resolve4.mockResolvedValue(['203.0.113.10']);
        resolverMock.resolve6.mockResolvedValue(['2001:db8::10']);
        resolverMock.resolveMx.mockResolvedValue([]);
        resolverMock.resolveNs.mockResolvedValue(['ns1.example.com']);

        await inspector.inspect('example.com');

        expect(resolverMock.resolve4).toHaveBeenCalledWith('example.com');
        expect(resolverMock.resolve6).toHaveBeenCalledWith('example.com');
        expect(resolverMock.resolveMx).toHaveBeenCalledWith('example.com');
        expect(resolverMock.resolveNs).toHaveBeenCalledWith('example.com');
    });

    it('devuelve los registros consultados', async () => {
        resolverMock.resolve4.mockResolvedValue(['203.0.113.10']);
        resolverMock.resolve6.mockResolvedValue(['2001:db8::10']);
        resolverMock.resolveMx.mockResolvedValue([
            { exchange: 'mail.example.com', priority: 10 },
        ]);
        resolverMock.resolveNs.mockResolvedValue(['ns1.example.com']);

        const result = await inspector.inspect('example.com');

        expect(result).toEqual({
            a: ['203.0.113.10'],
            aaaa: ['2001:db8::10'],
            mx: [{ exchange: 'mail.example.com', priority: 10 }],
            ns: ['ns1.example.com'],
        });
    });

    it('rechaza un dominio vacío', async () => {
        await expect(inspector.inspect('')).rejects.toThrow();

        expect(resolverMock.resolve4).not.toHaveBeenCalled();
    });

    it('rechaza un dominio con formato inválido', async () => {
        await expect(
            inspector.inspect('esto no es un dominio'),
        ).rejects.toThrow();

        expect(resolverMock.resolve4).not.toHaveBeenCalled();
    });

    it('devuelve listas vacías cuando las consultas no encuentran registros', async () => {
        resolverMock.resolve4.mockResolvedValue([]);
        resolverMock.resolve6.mockResolvedValue([]);
        resolverMock.resolveMx.mockResolvedValue([]);
        resolverMock.resolveNs.mockResolvedValue([]);

        const result = await inspector.inspect('example.com');

        expect(result).toEqual({
            a: [],
            aaaa: [],
            mx: [],
            ns: [],
        });
    });

    it('propaga los errores inesperados de resolución DNS', async () => {
        resolverMock.resolve4.mockRejectedValue(
            new Error('Fallo de resolución DNS'),
        );

        resolverMock.resolve6.mockResolvedValue([]);
        resolverMock.resolveMx.mockResolvedValue([]);
        resolverMock.resolveNs.mockResolvedValue([]);

        await expect(
            inspector.inspect('example.com'),
        ).rejects.toThrow('Fallo de resolución DNS');
    });
});

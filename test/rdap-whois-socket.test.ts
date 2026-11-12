import { EventEmitter } from 'node:events';
import { afterEach, describe, expect, it, jest } from '@jest/globals';

type MockSocket = EventEmitter & {
    write: (...args: unknown[]) => unknown;
    destroy: (...args: unknown[]) => unknown;
};

type MockReply = string | Error | 'timeout' | 'close' | 'late-data-bootstrap';

function installNetMock(replies: MockReply[]) {
    const sockets: MockSocket[] = [];
    const createConnection = jest.fn(() => {
        const socket = Object.assign(new EventEmitter(), {
            write: jest.fn(),
            destroy: jest.fn(),
        }) as MockSocket;
        const reply = replies.shift();
        sockets.push(socket);

        setImmediate(() => {
            socket.emit('connect');

            if (reply === 'timeout') {
                return;
            }

            if (reply === 'close') {
                socket.emit('close');
                return;
            }

            if (reply === 'late-data-bootstrap') {
                socket.emit(
                    'data',
                    'domain: COM\nwhois: whois.registry.example\n',
                );
                socket.emit('end');
                socket.emit('data', 'ignored after end');
                socket.emit('close');
                return;
            }

            if (reply instanceof Error) {
                socket.emit('error', reply);
                return;
            }

            const response = reply ?? '';
            const splitAt = Math.min(4, response.length);
            socket.emit('data', Buffer.from(response.slice(0, splitAt)));
            socket.emit('data', response.slice(splitAt));
            socket.emit('end');
            socket.emit('close');
        });

        return socket;
    });

    jest.doMock('node:net', () => ({ createConnection }));
    return { createConnection, sockets };
}

async function createInspector(
    replies: MockReply[],
    options: { timeoutMs?: number; maxWhoisResponseBytes?: number } = {},
) {
    jest.resetModules();
    const netMock = installNetMock(replies);
    const { RdapInspector } = await import('../src/services/rdap-inspector');
    const fetchFn = async () => ({
        ok: true,
        status: 200,
        json: async () => ({ services: [] }),
    } as Response);
    const inspector = new RdapInspector({
        fetchFn: fetchFn as typeof fetch,
        timeoutMs: options.timeoutMs ?? 100,
        maxWhoisResponseBytes: options.maxWhoisResponseBytes ?? 256,
    });

    return { inspector, ...netMock };
}

describe('RdapInspector · transporte WHOIS', () => {
    afterEach(() => {
        jest.dontMock('node:net');
        jest.resetModules();
    });

    it('consulta WHOIS mediante sockets y convierte sus campos', async () => {
        const { inspector, sockets } = await createInspector([
            'domain: COM\nwhois: whois.registry.example\n',
            'Domain Name: EXAMPLE.COM\nCreation Date: 2000-01-01\n',
        ]);

        const result = await inspector.inspect('example.com');

        expect(result.domain).toBe('example.com');
        expect(result.creationDate).toBe('2000-01-01');
        expect(sockets).toHaveLength(2);
        expect(sockets[0]?.write).toHaveBeenCalledWith('com\r\n');
        expect(sockets[1]?.write).toHaveBeenCalledWith('example.com\r\n');
    });

    it('propaga los errores del socket con un mensaje de WHOIS', async () => {
        const { inspector } = await createInspector([
            new Error('conexión rechazada'),
        ]);

        await expect(inspector.inspect('example.com')).rejects.toThrow(
            'Falló la conexión WHOIS: conexión rechazada',
        );
    });

    it('corta respuestas WHOIS que exceden el límite configurado', async () => {
        const { inspector } = await createInspector(
            ['respuesta demasiado extensa'],
            { maxWhoisResponseBytes: 8 },
        );

        await expect(inspector.inspect('example.com')).rejects.toThrow(
            'La respuesta WHOIS superó el límite de 8 bytes.',
        );
    });

    it('termina la consulta WHOIS cuando alcanza el timeout', async () => {
        const { inspector } = await createInspector(
            ['timeout'],
            { timeoutMs: 15 },
        );

        await expect(inspector.inspect('example.com')).rejects.toThrow(
            'superó el límite de 15 ms',
        );
    });

    it('resuelve una conexión cerrada sin evento end con la respuesta acumulada', async () => {
        const { inspector } = await createInspector(['close']);

        await expect(inspector.inspect('example.com')).rejects.toThrow(
            'IANA WHOIS no devolvió un servidor de registro válido.',
        );
    });

    it('ignora datos tardíos recibidos después del evento end', async () => {
        const { inspector } = await createInspector([
            'late-data-bootstrap',
            'Domain Name: EXAMPLE.COM\n',
        ]);

        const result = await inspector.inspect('example.com');

        expect(result.domain).toBe('example.com');
    });
});

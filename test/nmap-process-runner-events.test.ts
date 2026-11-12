import { EventEmitter } from 'node:events';

import {
    afterEach,
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';

type FakeChild = EventEmitter & {
    stdout: EventEmitter;
    stderr: EventEmitter;
    kill: (...args: unknown[]) => unknown;
};

function createFakeChild(): FakeChild {
    return Object.assign(new EventEmitter(), {
        stdout: new EventEmitter(),
        stderr: new EventEmitter(),
        kill: jest.fn(),
    }) as FakeChild;
}

async function createRunner(spawn: jest.Mock) {
    jest.resetModules();
    jest.doMock('node:child_process', () => ({ spawn }));
    const { ChildProcessNmapRunner } = await import(
        '../src/services/nmap-inspector'
    );

    return new ChildProcessNmapRunner();
}

describe('ChildProcessNmapRunner · eventos excepcionales', () => {
    afterEach(() => {
        jest.dontMock('node:child_process');
        jest.resetModules();
    });

    it('traduce un error sincrónico no estándar al crear el proceso', async () => {
        const spawn = jest.fn(() => {
            throw 'spawn failed';
        });
        const runner = await createRunner(spawn);

        await expect(
            runner.run('nmap', [], { timeoutMs: 1000, maxOutputBytes: 1024 }),
        ).rejects.toThrow('No se pudo iniciar Nmap.');
    });

    it('traduce un error sincrónico estándar al crear el proceso', async () => {
        const spawn = jest.fn(() => {
            throw new Error('invalid spawn options');
        });
        const runner = await createRunner(spawn);

        await expect(
            runner.run('nmap', [], { timeoutMs: 1000, maxOutputBytes: 1024 }),
        ).rejects.toThrow('No se pudo iniciar Nmap: invalid spawn options');
    });

    it('ignora datos de salida y cierre que llegan después de resolver un error', async () => {
        const child = createFakeChild();
        const spawn = jest.fn(() => child);
        const runner = await createRunner(spawn);
        const execution = runner.run(
            'nmap',
            [],
            { timeoutMs: 1000, maxOutputBytes: 1024 },
        );

        child.emit('error', new Error('process error'));
        child.stdout.emit('data', Buffer.from('late stdout'));
        child.stderr.emit('data', 'late stderr');
        child.emit('close', 1);

        await expect(execution).rejects.toThrow(
            'No se pudo iniciar Nmap: process error',
        );
    });

    it('mantiene el primer error cuando llega otro evento después de exceder la salida', async () => {
        const child = createFakeChild();
        const spawn = jest.fn(() => child);
        const runner = await createRunner(spawn);
        const execution = runner.run(
            'nmap',
            [],
            { timeoutMs: 1000, maxOutputBytes: 4 },
        );

        child.stdout.emit('data', Buffer.from('too much output'));
        child.emit('error', new Error('late process error'));

        await expect(execution).rejects.toThrow(
            'La salida de Nmap superó el límite de 4 bytes.',
        );
    });

    it('acepta fragmentos de salida entregados como texto y termina correctamente', async () => {
        const child = createFakeChild();
        const spawn = jest.fn(() => child);
        const runner = await createRunner(spawn);
        const execution = runner.run(
            'nmap',
            [],
            { timeoutMs: 1000, maxOutputBytes: 1024 },
        );

        child.stdout.emit('data', '<nmaprun/>');
        child.stderr.emit('data', 'diagnostic');
        child.emit('close', 0);

        await expect(execution).resolves.toEqual({
            stdout: '<nmaprun/>',
            stderr: 'diagnostic',
        });
    });
});

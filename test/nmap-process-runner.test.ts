import { describe, expect, it } from '@jest/globals';

import { ChildProcessNmapRunner } from '../src/services/nmap-inspector';

describe('ChildProcessNmapRunner', () => {
    const runner = new ChildProcessNmapRunner();

    it('ejecuta un proceso sin shell y captura stdout y stderr', async () => {
        const result = await runner.run(
            process.execPath,
            [
                '-e',
                "process.stdout.write('<nmaprun/>'); process.stderr.write('diagnostic');",
            ],
            {
                timeoutMs: 5000,
                maxOutputBytes: 1024,
            },
        );

        expect(result).toEqual({
            stdout: '<nmaprun/>',
            stderr: 'diagnostic',
        });
    });

    it('detiene el proceso que excede el tiempo configurado', async () => {
        await expect(
            runner.run(
                process.execPath,
                ['-e', 'setTimeout(() => {}, 5000)'],
                {
                    timeoutMs: 100,
                    maxOutputBytes: 1024,
                },
            ),
        ).rejects.toThrow('superó el límite de tiempo');
    });

    it('detiene el proceso que excede el límite de salida', async () => {
        await expect(
            runner.run(
                process.execPath,
                ['-e', "process.stdout.write('x'.repeat(10000))"],
                {
                    timeoutMs: 5000,
                    maxOutputBytes: 32,
                },
            ),
        ).rejects.toThrow('superó el límite de 32 bytes');
    });

    it('devuelve un error descriptivo cuando el ejecutable no existe', async () => {
        await expect(
            runner.run(
                `${process.execPath}.missing`,
                [],
                {
                    timeoutMs: 5000,
                    maxOutputBytes: 1024,
                },
            ),
        ).rejects.toThrow('No se pudo iniciar Nmap');
    });

    it('incluye el código y stderr cuando Nmap termina con error', async () => {
        await expect(
            runner.run(
                process.execPath,
                ['-e', "process.stderr.write('falló la ejecución'); process.exit(2)"],
                {
                    timeoutMs: 5000,
                    maxOutputBytes: 1024,
                },
            ),
        ).rejects.toThrow('Nmap terminó con código 2. falló la ejecución');
    });

    it('incluye el código de salida cuando el proceso falla sin stderr', async () => {
        await expect(
            runner.run(
                process.execPath,
                ['-e', 'process.exit(3)'],
                {
                    timeoutMs: 5000,
                    maxOutputBytes: 1024,
                },
            ),
        ).rejects.toThrow('Nmap terminó con código 3.');
    });
});

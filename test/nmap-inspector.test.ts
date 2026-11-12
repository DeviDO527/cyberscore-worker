import { beforeEach, describe, expect, it } from '@jest/globals';

import type { ValidatedTarget } from '../src/security/network-target-validator';
import {
    NmapInspector,
    type NmapProcessExecutionOptions,
    type NmapProcessResult,
    type NmapProcessRunner,
    type NmapTargetValidator,
} from '../src/services/nmap-inspector';

interface RunnerCall {
    binaryPath: string;
    args: string[];
    options: NmapProcessExecutionOptions;
}

class StubTargetValidator implements NmapTargetValidator {
    calls: string[] = [];
    result: ValidatedTarget = {
        hostname: 'example.com',
        addresses: ['8.8.8.8'],
    };
    error: Error | null = null;

    async validate(input: string): Promise<ValidatedTarget> {
        this.calls.push(input);

        if (this.error) {
            throw this.error;
        }

        return this.result;
    }
}

class StubNmapRunner implements NmapProcessRunner {
    calls: RunnerCall[] = [];
    error: Error | null = null;
    response: NmapProcessResult = {
        stdout: '<nmaprun></nmaprun>',
        stderr: '',
    };

    async run(
        binaryPath: string,
        args: string[],
        options: NmapProcessExecutionOptions,
    ): Promise<NmapProcessResult> {
        this.calls.push({ binaryPath, args, options });

        if (this.error) {
            throw this.error;
        }

        return this.response;
    }
}

describe('NmapInspector', () => {
    let validator: StubTargetValidator;
    let runner: StubNmapRunner;
    let inspector: NmapInspector;

    const authorization = {
        authorized: true,
        scope: 'example.com',
    };

    beforeEach(() => {
        validator = new StubTargetValidator();
        runner = new StubNmapRunner();
        inspector = new NmapInspector(validator, runner);
    });

    it('usa standard por defecto y conserva las opciones de extracción del notebook', async () => {
        const result = await inspector.inspect('example.com', authorization);

        expect(result.mode).toBe('standard');
        expect(validator.calls).toEqual(['example.com']);
        expect(runner.calls).toHaveLength(1);
        expect(runner.calls[0]?.args).toEqual([
            '-sT',
            '-sV',
            '--version-intensity',
            '2',
            '-Pn',
            '--top-ports',
            '1000',
            '-T4',
            '--open',
            '-oX',
            '-',
            '8.8.8.8',
        ]);
        expect(runner.calls[0]?.args).not.toContain('example.com');
        expect(runner.calls[0]?.binaryPath).toBe('nmap');
        expect(result.authorization).toEqual(authorization);
        expect(result.scans[0]).toEqual({
            address: '8.8.8.8',
            xml: '<nmaprun></nmaprun>',
        });
    });

    it('permite seleccionar el escaneo profundo para una inspección', async () => {
        const result = await inspector.inspect(
            'example.com',
            authorization,
            { mode: 'deep' },
        );

        expect(result.mode).toBe('deep');
        expect(runner.calls[0]?.args).toEqual([
            '-sT',
            '-sV',
            '--version-intensity',
            '2',
            '-Pn',
            '-p-',
            '-T4',
            '--open',
            '-oX',
            '-',
            '8.8.8.8',
        ]);
    });

    it('admite deep como modo predeterminado configurable y permite cambiarlo por inspección', async () => {
        const configuredInspector = new NmapInspector(
            validator,
            runner,
            { defaultMode: 'deep' },
        );

        const deepResult = await configuredInspector.inspect(
            'example.com',
            authorization,
        );
        const standardResult = await configuredInspector.inspect(
            'example.com',
            authorization,
            { mode: 'standard' },
        );

        expect(deepResult.mode).toBe('deep');
        expect(standardResult.mode).toBe('standard');
        expect(runner.calls[0]?.args).toContain('-p-');
        expect(runner.calls[1]?.args).toContain('--top-ports');
        expect(runner.calls[0]?.args).not.toContain('-g');
        expect(runner.calls[1]?.args).not.toContain('-g');
    });

    it('rechaza la inspección si falta la declaración afirmativa de autorización', async () => {
        await expect(
            inspector.inspect('example.com', {
                authorized: false,
                scope: 'example.com',
            }),
        ).rejects.toThrow('declaración explícita de autorización');

        expect(validator.calls).toEqual([]);
        expect(runner.calls).toEqual([]);
    });

    it('rechaza un alcance declarado diferente antes de validar o ejecutar Nmap', async () => {
        await expect(
            inspector.inspect('example.com', {
                authorized: true,
                scope: 'other.example',
            }),
        ).rejects.toThrow('coincidir exactamente');

        expect(validator.calls).toEqual([]);
        expect(runner.calls).toEqual([]);
    });

    it('rechaza un alcance cuyo valor no es texto', async () => {
        await expect(
            inspector.inspect('example.com', {
                authorized: true,
                scope: 42 as unknown as string,
            }),
        ).rejects.toThrow('alcance declarado');

        expect(validator.calls).toEqual([]);
        expect(runner.calls).toEqual([]);
    });

    it('rechaza un validador que devuelve un dominio distinto del autorizado', async () => {
        validator.result = {
            hostname: 'other.example',
            addresses: ['8.8.8.8'],
        };

        await expect(
            inspector.inspect('example.com', authorization),
        ).rejects.toThrow('no coincide con el alcance autorizado');

        expect(runner.calls).toEqual([]);
    });

    it('ejecuta únicamente contra cada dirección IP validada', async () => {
        validator.result = {
            hostname: 'example.com',
            addresses: ['8.8.8.8', '1.1.1.1', '8.8.8.8'],
        };

        const result = await inspector.inspect('example.com', authorization);

        expect(result.target.addresses).toEqual(['8.8.8.8', '1.1.1.1']);
        expect(runner.calls.map(call => call.args.at(-1))).toEqual([
            '8.8.8.8',
            '1.1.1.1',
        ]);
        expect(runner.calls.every(call => !call.args.includes('example.com'))).toBe(true);
    });

    it('añade el modo IPv6 al escanear una dirección validada IPv6', async () => {
        validator.result = {
            hostname: 'example.com',
            addresses: ['2606:4700:4700::1111'],
        };

        await inspector.inspect('example.com', authorization);

        expect(runner.calls[0]?.args).toContain('-6');
        expect(runner.calls[0]?.args.at(-1)).toBe('2606:4700:4700::1111');
    });

    it('rechaza listas vacías o direcciones inválidas del validador', async () => {
        validator.result = { hostname: 'example.com', addresses: [] };
        await expect(
            inspector.inspect('example.com', authorization),
        ).rejects.toThrow('no tiene direcciones IP escaneables');

        validator.result = {
            hostname: 'example.com',
            addresses: ['example.com'],
        };
        await expect(
            inspector.inspect('example.com', authorization),
        ).rejects.toThrow('dirección IP inválida');

        expect(runner.calls).toEqual([]);
    });

    it('cancela el escaneo si el resultado del validador supera el máximo de direcciones', async () => {
        validator.result = {
            hostname: 'example.com',
            addresses: ['8.8.8.8', '1.1.1.1'],
        };
        inspector = new NmapInspector(validator, runner, { maxTargets: 1 });

        await expect(
            inspector.inspect('example.com', authorization),
        ).rejects.toThrow('se cancela el escaneo');

        expect(runner.calls).toEqual([]);
    });

    it('usa los límites de tiempo configurados según la modalidad', async () => {
        inspector = new NmapInspector(validator, runner, {
            standardTimeoutMs: 10_000,
            deepTimeoutMs: 20_000,
            maxOutputBytes: 2048,
        });

        await inspector.inspect('example.com', authorization);
        await inspector.inspect('example.com', authorization, { mode: 'deep' });

        expect(runner.calls[0]?.options).toEqual({
            timeoutMs: 10_000,
            maxOutputBytes: 2048,
        });
        expect(runner.calls[1]?.options).toEqual({
            timeoutMs: 20_000,
            maxOutputBytes: 2048,
        });
    });

    it('propaga los fallos de ejecución y rechaza una salida vacía', async () => {
        runner.error = new Error('Nmap no está instalado');
        await expect(
            inspector.inspect('example.com', authorization),
        ).rejects.toThrow('Nmap no está instalado');

        runner.error = null;
        runner.response = { stdout: '  ', stderr: '' };
        await expect(
            inspector.inspect('example.com', authorization),
        ).rejects.toThrow('no devolvió XML');
    });

    it('rechaza modalidades no soportadas y configuraciones con límites inválidos', async () => {
        await expect(
            inspector.inspect(
                'example.com',
                authorization,
                { mode: 'udp' as 'standard' },
            ),
        ).rejects.toThrow("'standard' o 'deep'");

        expect(() =>
            new NmapInspector(validator, runner, { maxOutputBytes: 0 }),
        ).toThrow('maxOutputBytes debe ser un entero positivo');

        expect(runner.calls).toEqual([]);
    });

    it('rechaza si el validador no devuelve una lista de IPs', async () => {
        validator.result = {
            hostname: 'example.com',
            addresses: null as unknown as string[],
        };

        await expect(
            inspector.inspect('example.com', authorization),
        ).rejects.toThrow('El validador no devolvió una lista de direcciones IP.');
        expect(runner.calls).toEqual([]);
    });

    it('puede construirse con el ejecutor predeterminado sin iniciar Nmap', () => {
        expect(() => new NmapInspector(validator)).not.toThrow();
    });
});

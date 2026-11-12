import { spawn } from 'node:child_process';
import { isIP } from 'node:net';

import type { ValidatedTarget } from '../security/network-target-validator';

export type NmapScanMode = 'standard' | 'deep';

/** Explicit, per-scan confirmation that the caller may assess this exact domain. */
export interface NmapAuthorizationDeclaration {
    authorized: boolean;
    scope: string;
}

export interface NmapInspectionOptions {
    mode?: NmapScanMode;
}

export interface NmapInspectorConfig {
    /** The mode used when an individual inspection does not specify one. */
    defaultMode?: NmapScanMode;
    /** Executable name or absolute path. No shell is used to launch it. */
    binaryPath?: string;
    standardTimeoutMs?: number;
    deepTimeoutMs?: number;
    maxOutputBytes?: number;
    maxTargets?: number;
}

export interface NmapTargetValidator {
    validate(input: string): Promise<ValidatedTarget>;
}

export interface NmapProcessExecutionOptions {
    timeoutMs: number;
    maxOutputBytes: number;
}

export interface NmapProcessResult {
    stdout: string;
    stderr: string;
}

export interface NmapProcessRunner {
    run(
        binaryPath: string,
        args: string[],
        options: NmapProcessExecutionOptions,
    ): Promise<NmapProcessResult>;
}

export interface NmapHostScan {
    address: string;
    xml: string;
}

export interface NmapInspectionResult {
    target: ValidatedTarget;
    mode: NmapScanMode;
    authorization: NmapAuthorizationDeclaration;
    startedAt: string;
    completedAt: string;
    scans: NmapHostScan[];
}

const DEFAULT_STANDARD_TIMEOUT_MS = 120_000;
const DEFAULT_DEEP_TIMEOUT_MS = 900_000;
const DEFAULT_MAX_OUTPUT_BYTES = 16 * 1024 * 1024;
const DEFAULT_MAX_TARGETS = 16;

export class ChildProcessNmapRunner implements NmapProcessRunner {
    run(
        binaryPath: string,
        args: string[],
        options: NmapProcessExecutionOptions,
    ): Promise<NmapProcessResult> {
        return new Promise((resolve, reject) => {
            let child;

            try {
                child = spawn(binaryPath, args, {
                    shell: false,
                    windowsHide: true,
                    stdio: ['ignore', 'pipe', 'pipe'],
                });
            } catch (error: unknown) {
                reject(this.asExecutionError(error));
                return;
            }

            const stdoutChunks: Buffer[] = [];
            const stderrChunks: Buffer[] = [];
            let capturedBytes = 0;
            let settled = false;

            const timeout = setTimeout(() => {
                child.kill('SIGKILL');
                finishWithError(
                    new Error(
                        `Nmap superó el límite de tiempo de ${options.timeoutMs} ms.`,
                    ),
                );
            }, options.timeoutMs);

            const finishWithError = (error: Error): void => {
                if (settled) {
                    return;
                }

                settled = true;
                clearTimeout(timeout);
                reject(error);
            };

            const capture = (
                destination: Buffer[],
                chunk: Buffer | string,
            ): void => {
                if (settled) {
                    return;
                }

                const buffer = Buffer.isBuffer(chunk)
                    ? chunk
                    : Buffer.from(chunk);

                if (
                    capturedBytes + buffer.length >
                    options.maxOutputBytes
                ) {
                    child.kill('SIGKILL');
                    finishWithError(
                        new Error(
                            `La salida de Nmap superó el límite de ${options.maxOutputBytes} bytes.`,
                        ),
                    );
                    return;
                }

                capturedBytes += buffer.length;
                destination.push(buffer);
            };

            child.stdout.on('data', (chunk: Buffer | string) => {
                capture(stdoutChunks, chunk);
            });

            child.stderr.on('data', (chunk: Buffer | string) => {
                capture(stderrChunks, chunk);
            });

            child.once('error', error => {
                finishWithError(
                    new Error(`No se pudo iniciar Nmap: ${error.message}`),
                );
            });

            child.once('close', code => {
                if (settled) {
                    return;
                }

                clearTimeout(timeout);

                if (code !== 0) {
                    const stderr = Buffer.concat(stderrChunks)
                        .toString('utf8')
                        .trim()
                        .slice(0, 500);
                    const detail = stderr ? ` ${stderr}` : '';

                    finishWithError(
                        new Error(
                            `Nmap terminó con código ${String(code)}.${detail}`,
                        ),
                    );
                    return;
                }

                settled = true;
                resolve({
                    stdout: Buffer.concat(stdoutChunks).toString('utf8'),
                    stderr: Buffer.concat(stderrChunks).toString('utf8'),
                });
            });
        });
    }

    private asExecutionError(error: unknown): Error {
        return error instanceof Error
            ? new Error(`No se pudo iniciar Nmap: ${error.message}`)
            : new Error('No se pudo iniciar Nmap.');
    }
}

export class NmapInspector {
    private readonly defaultMode: NmapScanMode;
    private readonly binaryPath: string;
    private readonly standardTimeoutMs: number;
    private readonly deepTimeoutMs: number;
    private readonly maxOutputBytes: number;
    private readonly maxTargets: number;

    constructor(
        private readonly targetValidator: NmapTargetValidator,
        private readonly processRunner: NmapProcessRunner =
            new ChildProcessNmapRunner(),
        config: NmapInspectorConfig = {},
    ) {
        this.defaultMode = this.validateMode(
            config.defaultMode ?? 'standard',
        );
        this.binaryPath = config.binaryPath?.trim() || 'nmap';
        this.standardTimeoutMs = this.positiveInteger(
            config.standardTimeoutMs ?? DEFAULT_STANDARD_TIMEOUT_MS,
            'standardTimeoutMs',
        );
        this.deepTimeoutMs = this.positiveInteger(
            config.deepTimeoutMs ?? DEFAULT_DEEP_TIMEOUT_MS,
            'deepTimeoutMs',
        );
        this.maxOutputBytes = this.positiveInteger(
            config.maxOutputBytes ?? DEFAULT_MAX_OUTPUT_BYTES,
            'maxOutputBytes',
        );
        this.maxTargets = this.positiveInteger(
            config.maxTargets ?? DEFAULT_MAX_TARGETS,
            'maxTargets',
        );
    }

    async inspect(
        domain: string,
        authorization: NmapAuthorizationDeclaration,
        options: NmapInspectionOptions = {},
    ): Promise<NmapInspectionResult> {
        this.assertAuthorization(domain, authorization);

        const target = await this.targetValidator.validate(domain);
        const normalizedHostname = this.normalizeScope(target.hostname);

        if (
            !normalizedHostname ||
            normalizedHostname !== this.normalizeScope(domain) ||
            normalizedHostname !== this.normalizeScope(authorization.scope)
        ) {
            throw new Error(
                'El dominio validado no coincide con el alcance autorizado.',
            );
        }

        const addresses = this.validatedAddresses(target.addresses);

        if (addresses.length === 0) {
            throw new Error(
                'El dominio validado no tiene direcciones IP escaneables.',
            );
        }

        if (addresses.length > this.maxTargets) {
            throw new Error(
                `El dominio resolvió más de ${this.maxTargets} direcciones IP; se cancela el escaneo.`,
            );
        }

        const mode = this.validateMode(options.mode ?? this.defaultMode);
        const startedAt = new Date().toISOString();
        const scans = await addresses.reduce<Promise<NmapHostScan[]>>(
            (pendingScans, address) => pendingScans.then(scanned =>
                this.scanAddress(address, mode).then(scan => {
                    scanned.push(scan);
                    return scanned;
                }),
            ),
            Promise.resolve([]),
        );

        return {
            target: {
                hostname: target.hostname,
                addresses,
            },
            mode,
            authorization: {
                authorized: true,
                scope: target.hostname,
            },
            startedAt,
            completedAt: new Date().toISOString(),
            scans,
        };
    }

    private assertAuthorization(
        domain: string,
        authorization: NmapAuthorizationDeclaration,
    ): void {
        if (authorization?.authorized !== true) {
            throw new Error(
                'Nmap requiere una declaración explícita de autorización.',
            );
        }

        const requestedScope = this.normalizeScope(domain);
        const declaredScope = this.normalizeScope(authorization.scope);

        if (!requestedScope || !declaredScope || requestedScope !== declaredScope) {
            throw new Error(
                'El alcance declarado debe coincidir exactamente con el dominio solicitado.',
            );
        }
    }

    private normalizeScope(value: unknown): string {
        return typeof value === 'string'
            ? value.trim().toLowerCase().replace(/\.$/, '')
            : '';
    }

    private validatedAddresses(addresses: string[]): string[] {
        if (!Array.isArray(addresses)) {
            throw new TypeError(
                'El validador no devolvió una lista de direcciones IP.',
            );
        }

        const uniqueAddresses: string[] = [];
        const seen = new Set<string>();

        for (const address of addresses) {
            if (typeof address !== 'string' || isIP(address) === 0) {
                throw new Error(
                    'El validador devolvió una dirección IP inválida.',
                );
            }

            const key = address.toLowerCase();

            if (!seen.has(key)) {
                seen.add(key);
                uniqueAddresses.push(address);
            }
        }

        return uniqueAddresses;
    }

    private buildArguments(
        address: string,
        mode: NmapScanMode,
    ): string[] {
        const args = [
            '-sT',
            '-sV',
            '--version-intensity',
            '2',
            '-Pn',
        ];

        if (isIP(address) === 6) {
            args.push('-6');
        }

        if (mode === 'deep') {
            args.push('-p-');
        } else {
            args.push('--top-ports', '1000');
        }

        // -g (source port) no aplica a TCP Connect (-sT): Nmap lo rechaza
        // para este tipo de escaneo. Sin esa opción se conserva el mismo
        // comportamiento efectivo del comando Python, donde -g era ignorado.
        args.push('-T4', '--open', '-oX', '-', address);

        return args;
    }

    private async scanAddress(
        address: string,
        mode: NmapScanMode,
    ): Promise<NmapHostScan> {
        const execution = await this.processRunner.run(
            this.binaryPath,
            this.buildArguments(address, mode),
            {
                timeoutMs:
                    mode === 'deep'
                        ? this.deepTimeoutMs
                        : this.standardTimeoutMs,
                maxOutputBytes: this.maxOutputBytes,
            },
        );

        if (!execution.stdout.trim()) {
            throw new Error(
                `Nmap no devolvió XML para la dirección validada ${address}.`,
            );
        }

        return {
            address,
            xml: execution.stdout,
        };
    }

    private validateMode(mode: unknown): NmapScanMode {
        if (mode !== 'standard' && mode !== 'deep') {
            throw new Error(
                "La modalidad Nmap debe ser 'standard' o 'deep'.",
            );
        }

        return mode;
    }

    private positiveInteger(value: number, name: string): number {
        if (!Number.isSafeInteger(value) || value <= 0) {
            throw new Error(`${name} debe ser un entero positivo.`);
        }

        return value;
    }
}

import tls from 'node:tls';

import { ValidatedTarget } from '../security/network-target-validator';

export interface TlsInspection {
    authorized: boolean;
    authorizationError?: string;
    protocol: string;
    validFrom: string;
    validTo: string;
    subject: Record<string, unknown>;
    issuer: Record<string, unknown>;
}

export interface TlsInspectorDependency {
    inspect(target: ValidatedTarget): Promise<TlsInspection>;
}

export interface TlsTargetValidatorDependency {
    validate(domain: string): Promise<ValidatedTarget>;
}

export class TlsInspector {
    constructor(
        private readonly validator: TlsTargetValidatorDependency,
        private readonly inspector: TlsInspectorDependency =
            new NodeTlsInspector(),
    ) {}

    async inspect(domain: string): Promise<TlsInspection> {
        if (
            typeof domain !== 'string' ||
            domain.trim().length === 0
        ) {
            throw new Error('El dominio es obligatorio.');
        }

        const normalizedDomain = domain.trim();

        const validDomain =
            normalizedDomain.length <= 253 &&
            normalizedDomain.includes('.') &&
            /^(?=.{1,253}$)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?))*$/.test(
                normalizedDomain,
            );

        if (!validDomain) {
            throw new Error('El dominio no tiene un formato válido.');
        }

        // Validación previa a cualquier conexión TLS.
        const target = await this.validator.validate(normalizedDomain);

        if (
            !target ||
            !target.hostname ||
            !Array.isArray(target.addresses) ||
            target.addresses.length === 0
        ) {
            throw new Error('El dominio no tiene direcciones IP validadas.');
        }

        return this.inspector.inspect(target);
    }
}

class NodeTlsInspector implements TlsInspectorDependency {
    inspect(target: ValidatedTarget): Promise<TlsInspection> {
        const address = target.addresses[0];

        if (!address) {
            return Promise.reject(
                new Error('No existe una dirección IP validada para conectar.'),
            );
        }

        return new Promise((resolve, reject) => {
            const socket = tls.connect({
                host: address,
                port: 443,

                // Se conserva el hostname original para SNI.
                servername: target.hostname,

                // Permite inspeccionar certificados no confiables.
                // Su estado se registra mediante socket.authorized.
                rejectUnauthorized: false,
            });

            let settled = false;

            const finishWithError = (error: Error): void => {
                if (settled) {
                    return;
                }

                settled = true;
                socket.destroy();
                reject(error);
            };

            socket.setTimeout(10_000);

            socket.once('secureConnect', () => {
                if (settled) {
                    return;
                }

                try {
                    const certificate = socket.getPeerCertificate();

                    if (!certificate || Object.keys(certificate).length === 0) {
                        finishWithError(
                            new Error(
                                'El servidor no presentó un certificado TLS.',
                            ),
                        );
                        return;
                    }

                    const result: TlsInspection = {
                        authorized: socket.authorized,
                        protocol: socket.getProtocol() ?? 'unknown',
                        validFrom: certificate.valid_from ?? '',
                        validTo: certificate.valid_to ?? '',
                        subject: certificate.subject ?? {},
                        issuer: certificate.issuer ?? {},
                    };

                    if (socket.authorizationError) {
                        result.authorizationError =
                            String(socket.authorizationError);
                    }

                    settled = true;
                    socket.end();

                    resolve(result);
                } catch (error) {
                    finishWithError(
                        error instanceof Error
                            ? error
                            : new Error(
                                'Error desconocido durante la inspección TLS.',
                            ),
                    );
                }
            });

            socket.once('timeout', () => {
                finishWithError(
                    new Error(
                        'Tiempo de espera agotado durante la conexión TLS.',
                    ),
                );
            });

            socket.once('error', (error) => {
                finishWithError(error);
            });
        });
    }
}
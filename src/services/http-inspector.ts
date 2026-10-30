import https from 'node:https';

import { ValidatedTarget } from '../security/network-target-validator';

export interface HttpInspection {
    statusCode: number;
    headers: Record<string, string | string[] | undefined>;
}

export interface HttpInspectionDependency {
    inspect(target: ValidatedTarget): Promise<HttpInspection>;
}

export interface TargetValidatorDependency {
    validate(domain: string): Promise<ValidatedTarget>;
}

export class HttpInspector {
    constructor(
        private readonly validator: TargetValidatorDependency,
        private readonly inspector: HttpInspectionDependency =
            new NodeHttpInspector(),
    ) {}

    async inspect(domain: string): Promise<HttpInspection> {
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

        // Primero se valida la autorización y las direcciones IP.
        const target = await this.validator.validate(normalizedDomain);

        if (
            !target ||
            !target.hostname ||
            !Array.isArray(target.addresses) ||
            target.addresses.length === 0
        ) {
            throw new Error('El dominio no tiene direcciones IP validadas.');
        }

        // La conexión utiliza exclusivamente el destino validado.
        return this.inspector.inspect(target);
    }
}

class NodeHttpInspector implements HttpInspectionDependency {
    async inspect(target: ValidatedTarget): Promise<HttpInspection> {
        const address = target.addresses[0];

        if (!address) {
            throw new Error('No existe una dirección IP validada para conectar.');
        }

        return new Promise((resolve, reject) => {
            const request = https.request(
                {
                    hostname: address,
                    port: 443,
                    servername: target.hostname,
                    path: '/',
                    method: 'HEAD',
                    timeout: 10_000,
                    headers: {
                        Host: target.hostname,
                        'User-Agent': 'CyberScore-PYME/1.0',
                    },
                },
                (response) => {
                    const result: HttpInspection = {
                        statusCode: response.statusCode ?? 0,
                        headers: response.headers,
                    };

                    response.resume();
                    resolve(result);
                },
            );

            request.once('timeout', () => {
                request.destroy(
                    new Error(
                        'Tiempo de espera agotado durante la petición HTTP.',
                    ),
                );
            });

            request.once('error', (error) => {
                reject(error);
            });

            request.end();
        });
    }
}
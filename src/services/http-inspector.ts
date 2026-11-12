import https from 'node:https';

import { ValidatedTarget } from '../security/network-target-validator';

type HeaderValue = string | string[] | undefined;

export interface HttpInspection {
    statusCode: number;
    headers: Record<string, HeaderValue>;
    url: string;
    usesHttps: boolean;
    server: string | null;
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

        const target = await this.validator.validate(normalizedDomain);

        if (
            !target?.hostname ||
            !Array.isArray(target.addresses) ||
            target.addresses.length === 0
        ) {
            throw new Error('El dominio no tiene direcciones IP validadas.');
        }

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
                    method: 'GET',
                    timeout: 10_000,
                    headers: {
                        Host: target.hostname,
                        'User-Agent': 'CyberScore-PYME/1.0',
                    },
                },
                (response) => {
                    const serverHeader = response.headers.server;
                    const server = Array.isArray(serverHeader)
                        ? (serverHeader[0] ?? null)
                        : (serverHeader ?? null);

                    const result: HttpInspection = {
                        statusCode: response.statusCode ?? 0,
                        headers: response.headers,
                        url: `https://${target.hostname}/`,
                        usesHttps: true,
                        server,
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
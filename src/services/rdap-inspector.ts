import { createConnection } from 'node:net';
import { getDomain } from 'tldts';

export interface RdapEvent {
    eventAction?: string;
    eventDate?: string;
}

export interface RdapEntity {
    roles?: string[];
    vcardArray?: unknown[];
}

export interface RdapResponse {
    handle?: string;
    ldhName?: string;
    unicodeName?: string;
    status?: string[];
    events?: RdapEvent[];
    entities?: RdapEntity[];
}

export interface RdapDomainInfo {
    domain: string;
    statuses: string[];
    creationDate: string | null;
    expirationDate: string | null;
    updatedDate: string | null;
    registrar: string | null;
}

export type WhoisQueryFunction = (
    server: string,
    query: string,
) => Promise<string>;

export interface RdapInspectorOptions {
    /** Optional fixed RDAP endpoint for tests and controlled deployments. */
    baseUrl?: string;
    bootstrapUrl?: string;
    fetchFn?: typeof fetch;
    whoisQueryFn?: WhoisQueryFunction;
    timeoutMs?: number;
    maxWhoisResponseBytes?: number;
}

interface RdapBootstrapResponse {
    services?: Array<[string[], string[]]>;
}

const IANA_RDAP_BOOTSTRAP_URL = 'https://data.iana.org/rdap/dns.json';
const IANA_WHOIS_SERVER = 'whois.iana.org';
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_WHOIS_RESPONSE_BYTES = 256 * 1024;

function queryWhoisServer(
    server: string,
    query: string,
    timeoutMs: number,
    maxResponseBytes: number,
): Promise<string> {
    return new Promise((resolve, reject) => {
        const socket = createConnection({
            host: server,
            port: 43,
        });

        const chunks: Buffer[] = [];
        let responseBytes = 0;
        let settled = false;

        const finish = (error?: Error): void => {
            if (settled) {
                return;
            }

            settled = true;
            clearTimeout(timeout);
            socket.destroy();

            if (error) {
                reject(error);
                return;
            }

            resolve(Buffer.concat(chunks).toString('utf8'));
        };

        const timeout = setTimeout(() => {
            finish(
                new Error(
                    `La consulta WHOIS superó el límite de ${timeoutMs} ms.`,
                ),
            );
        }, timeoutMs);

        socket.once('connect', () => {
            socket.write(`${query}\r\n`);
        });

        socket.on('data', (chunk: Buffer | string) => {
            if (settled) {
                return;
            }

            const buffer = Buffer.isBuffer(chunk)
                ? chunk
                : Buffer.from(chunk);

            if (responseBytes + buffer.length > maxResponseBytes) {
                finish(
                    new Error(
                        `La respuesta WHOIS superó el límite de ${maxResponseBytes} bytes.`,
                    ),
                );
                return;
            }

            responseBytes += buffer.length;
            chunks.push(buffer);
        });

        socket.once('end', () => finish());
        socket.once('close', () => {
            if (!settled) {
                finish();
            }
        });
        socket.once('error', error => {
            finish(new Error(`Falló la conexión WHOIS: ${error.message}`));
        });
    });
}

export class RdapInspector {
    private readonly configuredBaseUrl: string | undefined;

    private readonly bootstrapUrl: string;

    private readonly fetchFn: typeof fetch;

    private readonly whoisQueryFn: WhoisQueryFunction;

    private readonly timeoutMs: number;

    private readonly maxWhoisResponseBytes: number;

    private bootstrapPromise: Promise<RdapBootstrapResponse> | undefined;

    constructor(options: RdapInspectorOptions = {}) {
        this.configuredBaseUrl = options.baseUrl?.replace(/\/$/, '');
        this.bootstrapUrl = options.bootstrapUrl ?? IANA_RDAP_BOOTSTRAP_URL;
        this.fetchFn = options.fetchFn ?? fetch;
        this.whoisQueryFn = options.whoisQueryFn ?? ((server, query) =>
            queryWhoisServer(
                server,
                query,
                this.timeoutMs,
                this.maxWhoisResponseBytes,
            ));
        this.timeoutMs = this.positiveInteger(
            options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
            'timeoutMs',
        );
        this.maxWhoisResponseBytes = this.positiveInteger(
            options.maxWhoisResponseBytes ?? DEFAULT_MAX_WHOIS_RESPONSE_BYTES,
            'maxWhoisResponseBytes',
        );
    }

    async inspect(domain: string): Promise<RdapDomainInfo> {
        const normalizedDomain = this.normalizeDomain(domain);
        const registrableDomain = getDomain(normalizedDomain);

        if (!registrableDomain) {
            throw new Error(
                `No fue posible identificar el dominio registrable de ${normalizedDomain}.`,
            );
        }

        if (this.configuredBaseUrl) {
            return this.inspectRdap(
                this.configuredBaseUrl,
                registrableDomain,
                true,
            );
        }

        const tld = registrableDomain
            .slice(registrableDomain.lastIndexOf('.') + 1)
            .toLowerCase();
        let rdapError = `IANA no anuncia un servidor RDAP para .${tld}.`;

        try {
            const rdapUrls = await this.findRdapUrls(tld);

            if (rdapUrls.length > 0) {
                const { result, lastError } = await this.inspectRdapUrls(
                    rdapUrls,
                    registrableDomain,
                );

                if (result) {
                    return result;
                }

                rdapError = this.errorMessage(lastError);
            }
        } catch (error: unknown) {
            rdapError = this.errorMessage(error);
        }

        try {
            return await this.inspectWhois(
                tld,
                registrableDomain,
            );
        } catch (error: unknown) {
            throw new Error(
                `No fue posible consultar los datos de registro para ${registrableDomain}. ` +
                    `RDAP: ${rdapError} WHOIS: ${this.errorMessage(error)}`,
            );
        }
    }

    private async inspectRdap(
        baseUrl: string,
        domain: string,
        baseUrlContainsDomainPath: boolean,
    ): Promise<RdapDomainInfo> {
        const domainPath = baseUrlContainsDomainPath
            ? `/${encodeURIComponent(domain)}`
            : `/domain/${encodeURIComponent(domain)}`;
        const url = `${baseUrl.replace(/\/$/, '')}${domainPath}`;

        const response = await this.fetchFn(url, {
            headers: {
                Accept: 'application/rdap+json, application/json',
            },
            signal: AbortSignal.timeout(this.timeoutMs),
        });

        if (!response.ok) {
            throw new Error(
                `No fue posible consultar RDAP para ${domain}: HTTP ${response.status}`,
            );
        }

        const data = await response.json() as RdapResponse;

        return {
            domain: (
                data.ldhName ??
                data.unicodeName ??
                domain
            ).toLowerCase(),
            statuses: data.status ?? [],
            creationDate: this.findEventDate(
                data.events,
                'registration',
            ),
            expirationDate: this.findEventDate(
                data.events,
                'expiration',
            ),
            updatedDate: this.findEventDate(
                data.events,
                'last changed',
            ),
            registrar: this.findRegistrar(
                data.entities,
            ),
        };
    }

    private inspectRdapUrls(
        urls: string[],
        domain: string,
    ): Promise<{
        result: RdapDomainInfo | null;
        lastError: unknown;
    }> {
        let result: RdapDomainInfo | null = null;
        let lastError: unknown;
        const attempts = urls.reduce<Promise<void>>(
            (previousAttempt, url) => previousAttempt
                .then(() => result ?? this.inspectRdap(url, domain, false))
                .then(
                    inspection => {
                        if (inspection) {
                            result = inspection;
                        }
                    },
                    (error: unknown) => {
                        lastError = error;
                    },
                ),
            Promise.resolve(),
        );

        return attempts.then(() => ({ result, lastError }));
    }

    private async inspectWhois(
        tld: string,
        domain: string,
    ): Promise<RdapDomainInfo> {
        const bootstrapResponse = await this.whoisQueryFn(
            IANA_WHOIS_SERVER,
            tld,
        );
        const whoisServer = this.extractWhoisServer(bootstrapResponse);
        const response = await this.whoisQueryFn(
            whoisServer,
            domain,
        );

        return this.parseWhoisResponse(
            response,
            whoisServer,
            domain,
        );
    }

    private async findRdapUrls(tld: string): Promise<string[]> {
        const bootstrap = await this.loadRdapBootstrap();

        for (const service of bootstrap.services ?? []) {
            const [tlds, urls] = service;
            if (!tlds.some(value => value.toLowerCase() === tld)) {
                continue;
            }

            return urls.filter(url => {
                try {
                    return new URL(url).protocol === 'https:';
                } catch {
                    return false;
                }
            });
        }

        return [];
    }

    private async loadRdapBootstrap(): Promise<RdapBootstrapResponse> {
        this.bootstrapPromise ??= this.fetchRdapBootstrap();

        const currentPromise = this.bootstrapPromise;

        try {
            return await currentPromise;
        } catch (error: unknown) {
            if (this.bootstrapPromise === currentPromise) {
                this.bootstrapPromise = undefined;
            }

            throw error;
        }
    }

    private async fetchRdapBootstrap(): Promise<RdapBootstrapResponse> {
        const response = await this.fetchFn(this.bootstrapUrl, {
            headers: {
                Accept: 'application/json',
            },
            signal: AbortSignal.timeout(this.timeoutMs),
        });

        if (!response.ok) {
            throw new Error(
                `IANA RDAP bootstrap respondió con HTTP ${response.status}.`,
            );
        }

        const payload: unknown = await response.json();

        if (
            typeof payload !== 'object' ||
            payload === null ||
            !('services' in payload) ||
            !Array.isArray(payload.services)
        ) {
            throw new Error(
                'IANA RDAP bootstrap no contiene una lista de servicios válida.',
            );
        }

        return payload as RdapBootstrapResponse;
    }

    private extractWhoisServer(response: string): string {
        const match = /^(?:whois|refer|referralserver):\s*(?:whois:\/\/)?([^\s/]+)/im.exec(
            response,
        );
        const server = match?.[1]?.replace(/\.$/, '').toLowerCase();

        if (
            !server ||
            server.length > 253 ||
            !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i.test(server)
        ) {
            throw new Error(
                'IANA WHOIS no devolvió un servidor de registro válido.',
            );
        }

        return server;
    }

    private parseWhoisResponse(
        response: string,
        server: string,
        expectedDomain: string,
    ): RdapDomainInfo {
        const domain = this.findWhoisField(
            response,
            ['Domain Name', 'Domain'],
        );

        if (!domain) {
            throw new Error(
                `El servidor ${server} no devolvió un registro para ${expectedDomain}.`,
            );
        }

        const normalizedRecordDomain = domain
            .replace(/\.$/, '')
            .toLowerCase();

        if (normalizedRecordDomain !== expectedDomain.toLowerCase()) {
            throw new Error(
                `El servidor ${server} devolvió ${domain}, fuera del dominio registrable ${expectedDomain}.`,
            );
        }

        return {
            domain: normalizedRecordDomain,
            statuses: this.findWhoisFields(
                response,
                ['Domain Status', 'Status'],
            ),
            creationDate: this.findWhoisField(response, [
                'Creation Date',
                'Created On',
                'Created',
                'Registration Date',
                'Registered On',
            ]),
            expirationDate: this.findWhoisField(response, [
                'Registry Expiry Date',
                'Expiration Date',
                'Expiry Date',
                'Expires On',
                'Expiration Time',
            ]),
            updatedDate: this.findWhoisField(response, [
                'Updated Date',
                'Last Updated On',
                'Last Modified',
            ]),
            registrar: this.findWhoisField(response, [
                'Registrar',
                'Sponsoring Registrar',
                'Registrar Name',
            ]),
        };
    }

    private findWhoisField(
        response: string,
        fieldNames: string[],
    ): string | null {
        return this.findWhoisFields(response, fieldNames)[0] ?? null;
    }

    private findWhoisFields(
        response: string,
        fieldNames: string[],
    ): string[] {
        const fieldPattern = fieldNames
            .map(name => name.replace(/[.*+?^${}()|[\]\\]/g, String.raw`\$&`))
            .join('|');
        const pattern = new RegExp(
            String.raw`^(?:${fieldPattern}):\s*(.+?)\s*$`,
            'gim',
        );

        const values: string[] = [];
        let match: RegExpExecArray | null;

        while ((match = pattern.exec(response)) !== null) {
            const value = match[1]?.trim();

            if (value) {
                values.push(value);
            }
        }

        return values;
    }

    private findEventDate(
        events: RdapEvent[] | undefined,
        action: string,
    ): string | null {
        if (!events) {
            return null;
        }

        const event = events.find(
            currentEvent => currentEvent.eventAction?.toLowerCase() === action,
        );

        return event?.eventDate ?? null;
    }

    private findRegistrar(
        entities: RdapEntity[] | undefined,
    ): string | null {
        if (!entities) {
            return null;
        }

        const registrar = entities.find(entity =>
            entity.roles?.some(role => role.toLowerCase() === 'registrar'),
        );

        if (!registrar?.vcardArray) {
            return null;
        }

        return this.extractVcardName(registrar.vcardArray);
    }

    private extractVcardName(vcardArray: unknown[]): string | null {
        if (
            vcardArray.length < 2 ||
            !Array.isArray(vcardArray[1])
        ) {
            return null;
        }

        const properties = vcardArray[1];

        for (const property of properties) {
            if (!Array.isArray(property) || property.length < 4) {
                continue;
            }

            if (
                property[0] === 'fn' &&
                typeof property[3] === 'string'
            ) {
                return property[3];
            }
        }

        return null;
    }

    private normalizeDomain(domain: string): string {
        if (
            typeof domain !== 'string' ||
            domain.trim().length === 0
        ) {
            throw new Error(
                'El dominio es obligatorio para consultar RDAP',
            );
        }

        return domain
            .trim()
            .toLowerCase()
            .replace(/\.$/, '');
    }

    private positiveInteger(value: number, name: string): number {
        if (!Number.isSafeInteger(value) || value <= 0) {
            throw new Error(`${name} debe ser un entero positivo.`);
        }

        return value;
    }

    private errorMessage(error: unknown): string {
        return error instanceof Error ? error.message : String(error);
    }
}

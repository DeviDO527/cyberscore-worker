import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

export interface ResolvedAddress {
    address: string;
    family: number;
}

export interface DnsResolver {
    resolve(hostname: string): Promise<ResolvedAddress[]>;
}

type IPv4Octets = readonly [number, number, number, number];
type IPv6Groups = readonly [
    number,
    number,
    number,
    number,
    number,
    number,
    number,
    number,
];

const DEFAULT_DNS_RESOLVER: DnsResolver = {
    resolve: async hostname => lookup(hostname, {
        all: true,
        verbatim: true,
    }),
};

// Fixed special-use ranges stay in code so configuration cannot weaken SSRF protection.
const BLOCKED_IPV4_RANGES: ReadonlyArray<readonly [IPv4Octets, number]> = [
    [[0, 0, 0, 0], 8],
    [[10, 0, 0, 0], 8],
    [[100, 64, 0, 0], 10],
    [[127, 0, 0, 0], 8],
    [[169, 254, 0, 0], 16],
    [[172, 16, 0, 0], 12],
    [[192, 0, 0, 0], 24],
    [[192, 0, 2, 0], 24],
    [[192, 88, 99, 0], 24],
    [[192, 168, 0, 0], 16],
    [[198, 18, 0, 0], 15],
    [[198, 51, 100, 0], 24],
    [[203, 0, 113, 0], 24],
    [[224, 0, 0, 0], 4],
    [[240, 0, 0, 0], 4],
];

const GLOBAL_UNICAST_IPV6_NETWORK: IPv6Groups = [
    0x2000, 0, 0, 0, 0, 0, 0, 0,
];

const BLOCKED_IPV6_RANGES: ReadonlyArray<readonly [IPv6Groups, number]> = [
    [[0x2001, 0, 0, 0, 0, 0, 0, 0], 23],
    [[0x2001, 0x0db8, 0, 0, 0, 0, 0, 0], 32],
    [[0x2002, 0, 0, 0, 0, 0, 0, 0], 16],
    [[0x3fff, 0, 0, 0, 0, 0, 0, 0], 20],
];

export interface ValidatedTarget {
    hostname: string;
    addresses: string[];
}

export interface NetworkTargetValidatorOptions {
    allowAnyPublicDomain?: boolean;
}

export class NetworkTargetValidator {
    private readonly allowedDomains: Set<string>;
    private readonly allowAnyPublicDomain: boolean;

    constructor(
        allowedDomains: string[],
        private readonly dnsResolver: DnsResolver = DEFAULT_DNS_RESOLVER,
        options: NetworkTargetValidatorOptions = {},
    ) {
        this.allowedDomains = new Set(
            allowedDomains.map(
                domain => domain.toLowerCase().replace(/\.$/, ''),
            ),
        );

        this.allowAnyPublicDomain =
            options.allowAnyPublicDomain ?? false;
    }

    /** Permite un dominio únicamente después de que el worker confirma
     * la autorización registrada en MySQL para la evaluación reclamada. */
    authorizeRegisteredDomain(input: string): void {
        this.allowedDomains.add(this.normalizeHostname(input));
    }

    async validate(input: string): Promise<ValidatedTarget> {
        const hostname = this.normalizeHostname(input);

        if (!this.isAllowed(hostname)) {
            throw new Error(`Dominio no autorizado: ${hostname}`);
        }

        const resolved = await this.dnsResolver.resolve(hostname);

        if (!resolved.length) {
            throw new Error(
                `El dominio no tiene direcciones IP: ${hostname}`,
            );
        }

        for (const entry of resolved) {
            const actualFamily = isIP(entry.address);

            if (
                actualFamily === 0 ||
                actualFamily !== entry.family ||
                !this.isPublicIP(entry.address)
            ) {
                throw new Error(
                    `Dirección IP no permitida para ${hostname}: ${entry.address}`,
                );
            }
        }

        return {
            hostname,
            addresses: [
                ...new Set(resolved.map(entry => entry.address)),
            ],
        };
    }

    private normalizeHostname(input: string): string {
        if (typeof input !== 'string' || !input.trim()) {
            throw new Error('El dominio es obligatorio');
        }

        const hostname = input
            .trim()
            .toLowerCase()
            .replace(/\.$/, '');

        if (
            hostname.includes('://') ||
            hostname.includes('/') ||
            hostname.includes(':') ||
            hostname.includes('@') ||
            hostname.includes(' ')
        ) {
            throw new Error('Formato de dominio inválido');
        }

        if (
            hostname.length > 253 ||
            !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(
                hostname,
            )
        ) {
            throw new Error('Formato de dominio inválido');
        }

        return hostname;
    }

    private isAllowed(hostname: string): boolean {
        return (
            this.allowAnyPublicDomain ||
            this.allowedDomains.has(hostname)
        );
    }

    private isPublicIP(address: string): boolean {
        const family = isIP(address);

        if (family === 4) {
            return this.isPublicIPv4(address);
        }

        if (family === 6) {
            return this.isPublicIPv6(address);
        }

        return false;
    }

    private isPublicIPv4(address: string): boolean {
        return !BLOCKED_IPV4_RANGES.some(([network, prefix]) =>
            this.isIPv4InCidr(address, network, prefix),
        );
    }

    private isIPv4InCidr(
        address: string,
        network: string | IPv4Octets,
        prefix: number,
    ): boolean {
        const ipValue = this.ipv4ToNumber(address);
        const networkValue = typeof network === 'string'
            ? this.ipv4ToNumber(network)
            : this.ipv4PartsToNumber(network);

        if (ipValue === null || networkValue === null) {
            return false;
        }

        const mask =
            prefix === 0
                ? 0
                : (0xffffffff << (32 - prefix)) >>> 0;

        return (
            ((ipValue & mask) >>> 0) ===
            ((networkValue & mask) >>> 0)
        );
    }

    private ipv4ToNumber(address: string): number | null {
        if (isIP(address) !== 4) {
            return null;
        }

        return this.ipv4PartsToNumber(address.split('.').map(Number));
    }

    private ipv4PartsToNumber(parts: readonly number[]): number | null {
        if (
            parts.length !== 4 ||
            parts.some(
                part =>
                    !Number.isInteger(part) ||
                    part < 0 ||
                    part > 255,
            )
        ) {
            return null;
        }

        return (
            parts[0]! * 16777216 +
            parts[1]! * 65536 +
            parts[2]! * 256 +
            parts[3]!
        );
    }

    private isPublicIPv6(address: string): boolean {
        // Solo aceptamos global unicast dentro del prefijo global registrado.
        if (!this.isIPv6InCidr(address, GLOBAL_UNICAST_IPV6_NETWORK, 3)) {
            return false;
        }

        return !BLOCKED_IPV6_RANGES.some(([network, prefix]) =>
            this.isIPv6InCidr(address, network, prefix),
        );
    }

    private isIPv6InCidr(
        address: string,
        network: string | IPv6Groups,
        prefix: number,
    ): boolean {
        const ipGroups = this.parseIPv6(address);
        const networkGroups = typeof network === 'string'
            ? this.parseIPv6(network)
            : network;

        if (!ipGroups || !networkGroups) {
            return false;
        }

        const fullGroups = Math.floor(prefix / 16);
        const remainingBits = prefix % 16;

        for (let i = 0; i < fullGroups; i++) {
            if (ipGroups[i] !== networkGroups[i]) {
                return false;
            }
        }

        if (remainingBits === 0) {
            return true;
        }

        const mask = (0xffff << (16 - remainingBits)) & 0xffff;

        return (
            (ipGroups[fullGroups]! & mask) ===
            (networkGroups[fullGroups]! & mask)
        );
    }

    private parseIPv6(address: string): number[] | null {
        let normalized = address.toLowerCase();

        if (normalized.includes('%')) {
            return null;
        }

        // Convertir direcciones IPv4 representadas en IPv6.
        if (normalized.includes('.')) {
            const lastColon = normalized.lastIndexOf(':');

            if (lastColon === -1) {
                return null;
            }

            const ipv4Part = normalized.substring(lastColon + 1);
            const ipv4Value = this.ipv4ToNumber(ipv4Part);

            if (ipv4Value === null) {
                return null;
            }

            const firstGroup = Math.floor(ipv4Value / 65536);
            const secondGroup = ipv4Value % 65536;

            normalized =
                normalized.substring(0, lastColon + 1) +
                firstGroup.toString(16) +
                ':' +
                secondGroup.toString(16);
        }

        const separatorIndex = normalized.indexOf('::');

        let groups: string[];

        if (separatorIndex !== -1) {
            if (normalized.includes('::', separatorIndex + 2)) {
                return null;
            }

            const left = normalized
                .substring(0, separatorIndex)
                .split(':')
                .filter(Boolean);

            const right = normalized
                .substring(separatorIndex + 2)
                .split(':')
                .filter(Boolean);

            const missingGroups = 8 - left.length - right.length;

            if (missingGroups < 1) {
                return null;
            }

            groups = [
                ...left,
                ...new Array(missingGroups).fill('0'),
                ...right,
            ];
        } else {
            groups = normalized.split(':');
        }

        if (groups.length !== 8) {
            return null;
        }

        const parsed = groups.map(group => {
            if (!/^[0-9a-f]{1,4}$/.test(group)) {
                return null;
            }

            return Number.parseInt(group, 16);
        });

        if (parsed.includes(null)) {
            return null;
        }

        return parsed as number[];
    }
}

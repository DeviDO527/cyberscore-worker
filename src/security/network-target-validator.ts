import { lookup } from 'node:dns/promises';
import { isIP } from 'node:net';

export interface ResolvedAddress {
    address: string;
    family: number;
}

export interface DnsResolver {
    resolve(hostname: string): Promise<ResolvedAddress[]>;
}

export interface ValidatedTarget {
    hostname: string;
    addresses: string[];
}

export class NetworkTargetValidator {
    private readonly allowedDomains: Set<string>;

    constructor(
        allowedDomains: string[],
        private readonly dnsResolver: DnsResolver = {
            resolve: async (hostname) => {
                return lookup(hostname, {
                    all: true,
                    verbatim: true,
                });
            },
        },
    ) {
        this.allowedDomains = new Set(
            allowedDomains.map(domain => domain.toLowerCase().replace(/\.$/, '')),
        );
    }

    async validate(input: string): Promise<ValidatedTarget> {
        const hostname = this.normalizeHostname(input);

        if (!this.isAllowed(hostname)) {
            throw new Error(`Dominio no autorizado: ${hostname}`);
        }

        const resolved = await this.dnsResolver.resolve(hostname);

        if (!resolved.length) {
            throw new Error(`El dominio no tiene direcciones IP: ${hostname}`);
        }

        for (const entry of resolved) {
            if (!this.isPublicIP(entry.address)) {
                throw new Error(
                    `Dirección IP no permitida para ${hostname}: ${entry.address}`,
                );
            }
        }

        return {
            hostname,
            addresses: resolved.map(entry => entry.address),
        };
    }

    private normalizeHostname(input: string): string {
        if (typeof input !== 'string' || !input.trim()) {
            throw new Error('El dominio es obligatorio');
        }

        const hostname = input.trim().toLowerCase().replace(/\.$/, '');

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
            !/^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/.test(hostname)
        ) {
            throw new Error('Formato de dominio inválido');
        }

        return hostname;
    }

    private isAllowed(hostname: string): boolean {
        return this.allowedDomains.has(hostname);
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
        const parts = address.split('.').map(Number);
        
        if (
            parts.length !== 4 ||
            parts.some(part => !Number.isInteger(part) || part < 0 || part > 255)
        ) {
            return false;
        }
    
        // Ya comprobamos que existen los cuatro elementos.
        const a = parts[0]!;
        const b = parts[1]!;
    
        const blocked =
            a === 0 ||
            a === 10 ||
            a === 127 ||
            a >= 224 ||
            (a === 100 && b >= 64 && b <= 127) ||
            (a === 169 && b === 254) ||
            (a === 172 && b >= 16 && b <= 31) ||
            (a === 192 && b === 0) ||
            (a === 192 && b === 168) ||
            (a === 198 && (b === 18 || b === 19)) ||
            (a === 198 && b === 51) ||
            (a === 203 && b === 0);
    
        return !blocked;
    }

    private isPublicIPv6(address: string): boolean {
        const normalized = address.toLowerCase();

        // No se permiten direcciones IPv4 representadas en IPv6.
        if (
            normalized.startsWith('::ffff:') ||
            normalized === '::' ||
            normalized === '::1'
        ) {
            return false;
        }

        const firstGroup = parseInt(normalized.split(':')[0] || '0', 16);

        // Solo se aceptan direcciones globales unicast dentro de 2000::/3.
        if (firstGroup < 0x2000 || firstGroup > 0x3fff) {
            return false;
        }

        // Bloques especiales, de documentación y transición.
        if (
            normalized.startsWith('2001:db8:') ||
            normalized.startsWith('2002:') ||
            normalized.startsWith('3fff:')
        ) {
            return false;
        }

        return true;
    }
}

import { isIP } from 'node:net';

import type {
    NmapAuthorizationDeclaration,
    NmapInspectionResult,
    NmapScanMode,
} from '../services/nmap-inspector';

export interface NmapOpenPort {
    address: string;
    hostname: string;
    port: number;
    protocol: string;
    state: 'open';
    service: string;
    product: string | null;
    version: string | null;
    extraInfo: string | null;
    serviceDetails: string;
}

export interface NmapAnalysisResult {
    status: 'completed';
    hostname: string;
    addresses: string[];
    mode: NmapScanMode;
    authorization: NmapAuthorizationDeclaration;
    openPorts: NmapOpenPort[];
}

interface ParsedPort {
    port: number;
    protocol: string;
    service: string;
    product: string;
    version: string;
    extraInfo: string;
}

interface ParsedHost {
    address: string;
    ports: ParsedPort[];
}

interface XmlElement {
    attributes: string;
    content: string;
}

export class NmapAnalyzer {
    analyze(
        inspection: NmapInspectionResult,
    ): Promise<NmapAnalysisResult> {
        try {
            return Promise.resolve(this.analyzeValidated(inspection));
        } catch (error: unknown) {
            return Promise.reject(error);
        }
    }

    private analyzeValidated(
        inspection: NmapInspectionResult,
    ): NmapAnalysisResult {
        this.assertValidInspection(inspection);

        const authorizedAddresses = this.authorizedAddresses(inspection);
        const openPorts = new Map<string, NmapOpenPort>();

        this.collectOpenPorts(inspection, authorizedAddresses, openPorts);

        return {
            status: 'completed',
            hostname: inspection.target.hostname,
            addresses: [...inspection.target.addresses],
            mode: inspection.mode,
            authorization: {
                authorized: true,
                scope: inspection.target.hostname,
            },
            openPorts: [...openPorts.values()],
        };
    }

    private assertValidInspection(
        inspection: NmapInspectionResult,
    ): void {
        if (
            !inspection ||
            typeof inspection !== 'object' ||
            !inspection.target ||
            typeof inspection.target.hostname !== 'string' ||
            !Array.isArray(inspection.target.addresses) ||
            (inspection.mode !== 'standard' && inspection.mode !== 'deep') ||
            inspection.authorization?.authorized !== true ||
            inspection.authorization.scope !== inspection.target.hostname ||
            !Array.isArray(inspection.scans)
        ) {
            throw new Error(
                'El resultado de inspección Nmap no contiene un alcance autorizado válido.',
            );
        }
    }

    private authorizedAddresses(
        inspection: NmapInspectionResult,
    ): Set<string> {
        const authorizedAddresses = new Set(
            inspection.target.addresses
                .map(address => this.normalizeAddress(address))
                .filter((address): address is string => address !== null),
        );

        if (authorizedAddresses.size === 0) {
            throw new Error(
                'El resultado de inspección no contiene direcciones validadas.',
            );
        }

        return authorizedAddresses;
    }

    private collectOpenPorts(
        inspection: NmapInspectionResult,
        authorizedAddresses: Set<string>,
        openPorts: Map<string, NmapOpenPort>,
    ): void {
        for (const scan of inspection.scans) {
            const expectedAddress = this.normalizeAddress(scan.address);

            if (!expectedAddress || !authorizedAddresses.has(expectedAddress)) {
                throw new Error(
                    'El resultado Nmap incluye una dirección fuera del alcance validado.',
                );
            }

            const hosts = this.parseHosts(scan.xml);

            for (const host of hosts) {
                if (
                    host.address !== expectedAddress ||
                    !authorizedAddresses.has(host.address)
                ) {
                    continue;
                }

                this.addHostPorts(
                    host,
                    inspection.target.hostname,
                    openPorts,
                );
            }
        }
    }

    private addHostPorts(
        host: ParsedHost,
        hostname: string,
        openPorts: Map<string, NmapOpenPort>,
    ): void {
        for (const port of host.ports) {
            const key = `${host.address}/${port.protocol}/${port.port}`;

            if (openPorts.has(key)) {
                continue;
            }

            openPorts.set(key, {
                address: host.address,
                hostname,
                port: port.port,
                protocol: port.protocol,
                state: 'open',
                service: port.service,
                product: port.product || null,
                version: port.version || null,
                extraInfo: port.extraInfo || null,
                serviceDetails: this.serviceDetails(port),
            });
        }
    }

    private parseHosts(xml: string): ParsedHost[] {
        if (
            typeof xml !== 'string' ||
            !/<nmaprun\b/i.test(xml) ||
            !/<\/nmaprun\s*>/i.test(xml) ||
            /<!ENTITY\b/i.test(xml)
        ) {
            throw new Error('La salida de Nmap no contiene XML válido.');
        }

        return this.xmlElements(xml, 'host')
            .map(element => this.parseHost(element.content))
            .filter((host): host is ParsedHost => host !== null);
    }

    private parseHost(body: string): ParsedHost | null {
        const statusAttributes =
            this.xmlElements(body, 'status')[0]?.attributes ?? '';

        if (this.attribute(statusAttributes, 'state') !== 'up') {
            return null;
        }

        const address = this.findHostAddress(body);

        if (!address) {
            return null;
        }

        return {
            address,
            ports: this.parsePorts(body),
        };
    }

    private findHostAddress(body: string): string | null {
        for (const address of this.xmlElements(body, 'address')) {
            const addressType = this.attribute(address.attributes, 'addrtype');
            const candidate = this.attribute(address.attributes, 'addr');

            if (addressType !== 'ipv4' && addressType !== 'ipv6') {
                continue;
            }

            if (!candidate) {
                continue;
            }

            const normalizedAddress = this.normalizeAddress(candidate);

            if (normalizedAddress) {
                return normalizedAddress;
            }
        }

        return null;
    }

    private parsePorts(body: string): ParsedPort[] {
        const portsBlock = this.xmlElements(body, 'ports')[0]?.content ?? '';
        const ports: ParsedPort[] = [];

        for (const element of this.xmlElements(portsBlock, 'port')) {
            const port = this.parsePort(element);

            if (port) {
                ports.push(port);
            }
        }

        return ports;
    }

    private parsePort(element: XmlElement): ParsedPort | null {
        const stateAttributes =
            this.xmlElements(element.content, 'state')[0]?.attributes ?? '';

        if (this.attribute(stateAttributes, 'state') !== 'open') {
            return null;
        }

        const port = Number(this.attribute(element.attributes, 'portid'));
        const protocol = this.attribute(element.attributes, 'protocol').toUpperCase();

        if (!Number.isInteger(port) || port < 1 || port > 65_535 || !protocol) {
            return null;
        }

        const serviceAttributes =
            this.xmlElements(element.content, 'service')[0]?.attributes ?? '';

        return {
            port,
            protocol,
            service: this.attribute(serviceAttributes, 'name') || 'unknown',
            product: this.attribute(serviceAttributes, 'product'),
            version: this.attribute(serviceAttributes, 'version'),
            extraInfo: this.attribute(serviceAttributes, 'extrainfo'),
        };
    }

    private xmlElements(xml: string, tagName: string): XmlElement[] {
        const openTag = new RegExp(
            String.raw`<${tagName}(?=[\s/>])`,
            'gi',
        );
        const closeTag = new RegExp(
            String.raw`</${tagName}\s*>`,
            'gi',
        );
        const elements: XmlElement[] = [];

        while (openTag.exec(xml) !== null) {
            const attributesStart = openTag.lastIndex;
            const tagEnd = xml.indexOf('>', attributesStart);

            if (tagEnd < 0) {
                break;
            }

            let attributesEnd = tagEnd;

            while (
                attributesEnd > attributesStart &&
                /\s/.test(xml[attributesEnd - 1] ?? '')
            ) {
                attributesEnd -= 1;
            }

            const isSelfClosing = xml[attributesEnd - 1] === '/';

            if (isSelfClosing) {
                attributesEnd -= 1;
                elements.push({
                    attributes: xml.slice(attributesStart, attributesEnd),
                    content: '',
                });
                openTag.lastIndex = tagEnd + 1;
                continue;
            }

            closeTag.lastIndex = tagEnd + 1;
            const closeMatch = closeTag.exec(xml);

            if (!closeMatch) {
                break;
            }

            elements.push({
                attributes: xml.slice(attributesStart, attributesEnd),
                content: xml.slice(tagEnd + 1, closeMatch.index),
            });
            openTag.lastIndex = closeTag.lastIndex;
        }

        return elements;
    }

    private attribute(attributes: string, name: string): string {
        let cursor = 0;

        while (cursor < attributes.length) {
            cursor = this.skipAttributeSeparators(attributes, cursor);

            if (cursor >= attributes.length) {
                break;
            }

            const nameStart = cursor;
            cursor = this.attributeNameEnd(attributes, cursor);
            const attributeName = attributes.slice(nameStart, cursor);
            cursor = this.skipAttributeWhitespace(attributes, cursor);

            if (attributes[cursor] !== '=') {
                cursor += 1;
                continue;
            }

            const parsedValue = this.readAttributeValue(
                attributes,
                cursor + 1,
            );
            cursor = parsedValue.cursor;

            if (
                parsedValue.value !== null &&
                attributeName.toLowerCase() === name.toLowerCase()
            ) {
                return this.decodeEntities(parsedValue.value);
            }
        }

        return '';
    }

    private skipAttributeSeparators(attributes: string, cursor: number): number {
        while (/\s|\//.test(attributes[cursor] ?? '')) {
            cursor += 1;
        }

        return cursor;
    }

    private skipAttributeWhitespace(attributes: string, cursor: number): number {
        while (/\s/.test(attributes[cursor] ?? '')) {
            cursor += 1;
        }

        return cursor;
    }

    private attributeNameEnd(attributes: string, cursor: number): number {
        while (
            cursor < attributes.length &&
            !/[\s=/>]/.test(attributes[cursor] ?? '')
        ) {
            cursor += 1;
        }

        return cursor;
    }

    private readAttributeValue(
        attributes: string,
        initialCursor: number,
    ): { value: string | null; cursor: number } {
        let cursor = this.skipAttributeWhitespace(attributes, initialCursor);
        const quote = attributes[cursor];

        if (quote !== '"' && quote !== "'") {
            while (
                cursor < attributes.length &&
                !/\s/.test(attributes[cursor] ?? '')
            ) {
                cursor += 1;
            }

            return { value: null, cursor };
        }

        const valueStart = cursor + 1;
        const valueEnd = attributes.indexOf(quote, valueStart);

        if (valueEnd < 0) {
            return { value: null, cursor: attributes.length };
        }

        return {
            value: attributes.slice(valueStart, valueEnd),
            cursor: valueEnd + 1,
        };
    }

    private decodeEntities(value: string): string {
        return value.replace(
            /&(#x[\da-f]+|#\d+|amp|lt|gt|quot|apos);/gi,
            (entity, code: string) => {
                const namedEntities: Record<string, string> = {
                    amp: '&',
                    apos: "'",
                    gt: '>',
                    lt: '<',
                    quot: '"',
                };
                const normalized = code.toLowerCase();

                if (normalized in namedEntities) {
                    return namedEntities[normalized]!;
                }

                const numericValue = normalized.startsWith('#x')
                    ? Number.parseInt(normalized.slice(2), 16)
                    : Number.parseInt(normalized.slice(1), 10);

                try {
                    return String.fromCodePoint(numericValue);
                } catch {
                    return entity;
                }
            },
        );
    }

    private normalizeAddress(address: unknown): string | null {
        if (typeof address !== 'string') {
            return null;
        }

        if (isIP(address) === 4) {
            return address
                .split('.')
                .map(part => String(Number(part)))
                .join('.');
        }

        if (isIP(address) !== 6 || address.includes('%')) {
            return null;
        }

        const lower = address.toLowerCase();
        const separator = lower.indexOf('::');
        let groups: string[];

        if (separator >= 0) {
            const left = lower.slice(0, separator).split(':').filter(Boolean);
            const right = lower.slice(separator + 2).split(':').filter(Boolean);
            const missing = 8 - left.length - right.length;

            if (missing < 1) {
                return null;
            }

            groups = [...left, ...new Array(missing).fill('0'), ...right];
        } else {
            groups = lower.split(':');
        }

        if (groups.length !== 8 || groups.some(group => !/^[\da-f]{1,4}$/.test(group))) {
            return null;
        }

        return groups
            .map(group => Number.parseInt(group, 16).toString(16).padStart(4, '0'))
            .join(':');
    }

    private serviceDetails(port: ParsedPort): string {
        let details = port.service.toUpperCase();

        if (port.product) {
            details += ` (${port.product}`;

            if (port.version) {
                details += ` v${port.version}`;
            }

            if (port.extraInfo) {
                details += ` - ${port.extraInfo}`;
            }

            details += ')';
        }

        return details;
    }
}

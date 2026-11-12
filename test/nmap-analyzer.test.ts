import { describe, expect, it } from '@jest/globals';

import { NmapAnalyzer } from '../src/security/nmap-analyzer';
import type { NmapInspectionResult } from '../src/services/nmap-inspector';

const exampleXml = (address: string): string => `<?xml version="1.0"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap">
  <host>
    <status state="up" />
    <address addr="${address}" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" reason="syn-ack" />
        <service name="https" product="Apache httpd" version="2.4.58" extrainfo="Unix &amp; Linux" />
      </port>
      <port protocol="tcp" portid="22">
        <state state="closed" reason="reset" />
        <service name="ssh" product="OpenSSH" version="9.0" />
      </port>
      <port protocol="tcp" portid="8080">
        <state state="open" reason="syn-ack" />
        <service name="http-proxy" />
      </port>
    </ports>
  </host>
  <runstats><finished exit="success" /></runstats>
</nmaprun>`;

const inspectionFor = (
    xml = exampleXml('8.8.8.8'),
    overrides: Partial<NmapInspectionResult> = {},
): NmapInspectionResult => ({
    target: {
        hostname: 'example.com',
        addresses: ['8.8.8.8'],
    },
    mode: 'standard',
    authorization: {
        authorized: true,
        scope: 'example.com',
    },
    startedAt: '2026-11-08T12:00:00.000Z',
    completedAt: '2026-11-08T12:00:01.000Z',
    scans: [{ address: '8.8.8.8', xml }],
    ...overrides,
});

describe('NmapAnalyzer', () => {
    const analyzer = new NmapAnalyzer();

    it('extrae puerto, protocolo, estado, servicio, producto, versión y detalle como el worker Python', async () => {
        const result = await analyzer.analyze(inspectionFor());

        expect(result.openPorts).toEqual([
            {
                address: '8.8.8.8',
                hostname: 'example.com',
                port: 443,
                protocol: 'TCP',
                state: 'open',
                service: 'https',
                product: 'Apache httpd',
                version: '2.4.58',
                extraInfo: 'Unix & Linux',
                serviceDetails: 'HTTPS (Apache httpd v2.4.58 - Unix & Linux)',
            },
            {
                address: '8.8.8.8',
                hostname: 'example.com',
                port: 8080,
                protocol: 'TCP',
                state: 'open',
                service: 'http-proxy',
                product: null,
                version: null,
                extraInfo: null,
                serviceDetails: 'HTTP-PROXY',
            },
        ]);
        expect(result.status).toBe('completed');
        expect(result.mode).toBe('standard');
        expect(result.authorization).toEqual({
            authorized: true,
            scope: 'example.com',
        });
    });

    it('mantiene modo deep y los datos del alcance en el resultado analizado', async () => {
        const inspection = inspectionFor(exampleXml('8.8.8.8'), {
            mode: 'deep',
        });

        const result = await analyzer.analyze(inspection);

        expect(result.mode).toBe('deep');
        expect(result.hostname).toBe('example.com');
        expect(result.addresses).toEqual(['8.8.8.8']);
    });

    it('normaliza direcciones IPv6 y conserva puertos abiertos del objetivo validado', async () => {
        const xml = `<?xml version="1.0"?>
<nmaprun><host><status state="up" />
<address addr="2606:4700:4700:0:0:0:0:1111" addrtype="ipv6" />
<ports><port protocol="tcp" portid="443"><state state="open" />
<service name="https" product="nginx" version="1.25" /></port></ports>
</host></nmaprun>`;
        const inspection = inspectionFor(xml, {
            target: {
                hostname: 'example.com',
                addresses: ['2606:4700:4700::1111'],
            },
            scans: [{ address: '2606:4700:4700::1111', xml }],
        });

        const result = await analyzer.analyze(inspection);

        expect(result.openPorts[0]).toMatchObject({
            address: '2606:4700:4700:0000:0000:0000:0000:1111',
            port: 443,
            service: 'https',
            product: 'nginx',
            version: '1.25',
        });
    });

    it('omite hosts del XML que no corresponden a la IP de esa ejecución', async () => {
        const xml = `<nmaprun>
<host><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports></host>
<host><status state="up"/><address addr="1.1.1.1" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>
</ports></host>
</nmaprun>`;

        const result = await analyzer.analyze(inspectionFor(xml));

        expect(result.openPorts.map(port => port.port)).toEqual([443]);
    });

    it('omite puertos cerrados y hosts marcados como caídos', async () => {
        const xml = `<nmaprun>
<host><status state="down"/><address addr="8.8.8.8" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
</ports></host></nmaprun>`;

        const result = await analyzer.analyze(inspectionFor(xml));

        expect(result.openPorts).toEqual([]);
    });

    it('deduplica puertos repetidos para la misma IP', async () => {
        const xml = `<nmaprun>
<host><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports></host>
<host><status state="up"/><address addr="8.8.8.8" addrtype="ipv4"/><ports>
<port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
</ports></host></nmaprun>`;

        const result = await analyzer.analyze(inspectionFor(xml));

        expect(result.openPorts).toHaveLength(1);
    });

    it('rechaza resultados sin autorización afirmativa o con alcance inconsistente', async () => {
        const unauthorized = inspectionFor(undefined, {
            authorization: {
                authorized: false,
                scope: 'example.com',
            },
        });
        const mismatchedScope = inspectionFor(undefined, {
            authorization: {
                authorized: true,
                scope: 'other.example',
            },
        });

        await expect(analyzer.analyze(unauthorized)).rejects.toThrow(
            'alcance autorizado válido',
        );
        await expect(analyzer.analyze(mismatchedScope)).rejects.toThrow(
            'alcance autorizado válido',
        );
    });

    it('rechaza una ejecución asociada a una IP fuera de las direcciones validadas', async () => {
        const inspection = inspectionFor(undefined, {
            scans: [{ address: '1.1.1.1', xml: exampleXml('1.1.1.1') }],
        });

        await expect(analyzer.analyze(inspection)).rejects.toThrow(
            'fuera del alcance validado',
        );
    });

    it('rechaza XML sin el documento Nmap esperado', async () => {
        await expect(
            analyzer.analyze(inspectionFor('<not-nmap/>')),
        ).rejects.toThrow('no contiene XML válido');
    });

    it('rechaza un resultado que no incluye direcciones IP validadas', async () => {
        const inspection = inspectionFor(exampleXml('8.8.8.8'), {
            target: {
                hostname: 'example.com',
                addresses: ['not-an-ip', 'fe80::1%eth0'],
            },
        });

        await expect(
            analyzer.analyze(inspection),
        ).rejects.toThrow(
            'El resultado de inspección no contiene direcciones validadas.',
        );
    });

    it('omite hosts sin IP y puertos abiertos con datos inválidos', async () => {
        const xml = '<?xml version="1.0"?>\n<nmaprun>\n'
            + '  <host><status state="up" /><address addr="not-an-ip" addrtype="ipv4" />'
            + '<ports><port protocol="tcp" portid="80"><state state="open" /></port></ports></host>\n'
            + '  <host><status state="up" /><address addr="8.8.8.8" addrtype="ipv4" />'
            + '<ports><port protocol="tcp" portid="70000"><state state="open" /></port>'
            + '<port protocol="" portid="80"><state state="open" /></port></ports></host>\n'
            + '</nmaprun>';
        const result = await analyzer.analyze(inspectionFor(xml));

        expect(result.openPorts).toEqual([]);
    });

    it('decodifica referencias numéricas decimales y hexadecimales en servicios', async () => {
        const xml = '<?xml version="1.0"?>\n<nmaprun>\n'
            + '  <host><status state="up" /><address addr="8.8.8.8" addrtype="ipv4" />'
            + '<ports><port protocol="tcp" portid="80"><state state="open" />'
            + '<service name="web&#45;server" product="Example&#x20;HTTP" /></port></ports></host>\n'
            + '</nmaprun>';
        const result = await analyzer.analyze(inspectionFor(xml));

        expect(result.openPorts[0]).toMatchObject({
            service: 'web-server',
            product: 'Example HTTP',
            serviceDetails: 'WEB-SERVER (Example HTTP)',
        });
    });

    it('rechaza direcciones de destino que no son cadenas o IPv6 con IPv4 embebida', async () => {
        const inspection = inspectionFor(exampleXml('8.8.8.8'), {
            target: {
                hostname: 'example.com',
                addresses: [null, '::ffff:192.0.2.1'] as unknown as string[],
            },
        });

        await expect(
            analyzer.analyze(inspection),
        ).rejects.toThrow('El resultado de inspección no contiene direcciones validadas.');
    });

    it('conserva una referencia numérica Unicode fuera de rango en el XML', async () => {
        const xml = '<?xml version="1.0"?>\n<nmaprun>'
            + '<host><status state="up" /><address addr="8.8.8.8" addrtype="ipv4" />'
            + '<ports><port protocol="tcp" portid="80"><state state="open" />'
            + '<service name="service&#x110000;" /></port></ports></host></nmaprun>';
        const result = await analyzer.analyze(inspectionFor(xml));

        expect(result.openPorts[0]?.service).toBe('service&#x110000;');
    });

    it('tolera hosts sin estado o dirección válida y servicios sin nombre', async () => {
        const xml = '<nmaprun>'
            + '<host><address addr="8.8.8.8" addrtype="ipv4" /></host>'
            + '<host><status state="up" />'
            + '<address addr="8.8.8.8" addrtype="mac" /></host>'
            + '<host><status state="up" />'
            + '<address addr="8.8.8.8" addrtype="ipv4" />'
            + '<ports><port protocol="tcp" portid="8443">'
            + '<state state="open" /></port></ports></host>'
            + '</nmaprun>';
        const result = await analyzer.analyze(inspectionFor(xml));

        expect(result.openPorts).toEqual([
            expect.objectContaining({
                address: '8.8.8.8',
                port: 8443,
                service: 'unknown',
            }),
        ]);
    });

    it('acepta un documento Nmap válido sin hosts', async () => {
        const result = await analyzer.analyze(
            inspectionFor('<nmaprun></nmaprun>'),
        );

        expect(result.openPorts).toEqual([]);
    });

    it('tolera espacios en atributos y continúa cuando una dirección no incluye addr', async () => {
        const xml = '<nmaprun><host    >'
            + '<status state = "up" />'
            + '<address addrtype = "ipv4" />'
            + '<address addrtype = "ipv4" addr = "8.8.8.8" />'
            + '<ports><port protocol="tcp" portid="8443">'
            + '<state state="open" /></port></ports>'
            + '</host></nmaprun>';
        const result = await analyzer.analyze(inspectionFor(xml));

        expect(result.openPorts).toEqual([
            expect.objectContaining({ address: '8.8.8.8', port: 8443 }),
        ]);
    });

    it('ignora atributos XML sin valor al buscar otros atributos', async () => {
        const xml = '<nmaprun><host><status state="up" />'
            + '<address addr="8.8.8.8" addrtype="ipv4" />'
            + '<ports><port protocol="tcp" portid="443">'
            + '<state state="open" />'
            + '<service name="https" vendor />'
            + '</port></ports></host></nmaprun>';
        const result = await analyzer.analyze(inspectionFor(xml));

        expect(result.openPorts[0]).toMatchObject({
            service: 'https',
            product: null,
        });
    });

    it.each([
        '<nmaprun><host </nmaprun>',
        '<nmaprun><host><status state="up" /></nmaprun>',
        '<nmaprun></nmaprun><host ',
    ])('omite fragmentos XML incompletos sin fallar: %s', async fragment => {
        const result = await analyzer.analyze(
            inspectionFor(fragment),
        );

        expect(result.openPorts).toEqual([]);
    });

    it.each([
        '<status state=up />',
        '<status state="up />',
    ])('omite hosts con atributos XML mal formados: %s', async status => {
        const xml = '<nmaprun><host>'
            + status
            + '<address addrtype="ipv4" addr="8.8.8.8" />'
            + '</host></nmaprun>';
        const result = await analyzer.analyze(inspectionFor(xml));

        expect(result.openPorts).toEqual([]);
    });
});

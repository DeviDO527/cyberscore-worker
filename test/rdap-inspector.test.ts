import {
    describe,
    expect,
    it,
    jest,
} from '@jest/globals';

import {
    RdapInspector,
} from '../src/services/rdap-inspector';

describe('RdapInspector', () => {
    interface FetchMock {
        (...args: Parameters<typeof fetch>): Promise<Response>;
        mockResolvedValue(
            value: Response,
        ): FetchMock;
        mockResolvedValueOnce(
            value: Response,
        ): FetchMock;
        mockRejectedValue(value: unknown): FetchMock;
        mock: {
            calls: unknown[][];
        };
    }

    function createFetchMock(): FetchMock {
        return jest.fn() as unknown as FetchMock;
    }

    function createFetchResponse(
        body: unknown,
        options: {
            ok?: boolean;
            status?: number;
        } = {},
    ): Response {
        return {
            ok: options.ok ?? true,
            status: options.status ?? 200,
            json: async () => body,
        } as Response;
    }

    it(
        'consulta el dominio y extrae la información principal de RDAP',
        async () => {
            const fetchFn = createFetchMock();

            fetchFn.mockResolvedValue(
                createFetchResponse({
                    ldhName: 'example.com',
                    status: [
                        'active',
                        'ok',
                    ],
                    events: [
                        {
                            eventAction:
                                'registration',
                            eventDate:
                                '2020-01-15T10:00:00Z',
                        },
                        {
                            eventAction:
                                'expiration',
                            eventDate:
                                '2030-01-15T10:00:00Z',
                        },
                        {
                            eventAction:
                                'last changed',
                            eventDate:
                                '2025-05-10T12:00:00Z',
                        },
                    ],
                    entities: [
                        {
                            roles: [
                                'registrar',
                            ],
                            vcardArray: [
                                'vcard',
                                [
                                    [
                                        'version',
                                        {},
                                        'text',
                                        '4.0',
                                    ],
                                    [
                                        'fn',
                                        {},
                                        'text',
                                        'Example Registrar Inc.',
                                    ],
                                ],
                            ],
                        },
                    ],
                }),
            );

            const inspector = new RdapInspector({
                fetchFn: fetchFn as typeof fetch,
                baseUrl:
                    'https://rdap.example.test/domain',
            });

            const result = await inspector.inspect(
                'Example.COM',
            );

            expect(fetchFn).toHaveBeenCalledWith(
                'https://rdap.example.test/domain/example.com',
                expect.objectContaining({
                    headers: {
                        Accept:
                            'application/rdap+json, application/json',
                    },
                }),
            );

            expect(result).toEqual({
                domain: 'example.com',
                statuses: [
                    'active',
                    'ok',
                ],
                creationDate:
                    '2020-01-15T10:00:00Z',
                expirationDate:
                    '2030-01-15T10:00:00Z',
                updatedDate:
                    '2025-05-10T12:00:00Z',
                registrar:
                    'Example Registrar Inc.',
            });
        },
    );

    it(
        'normaliza el dominio antes de realizar la consulta',
        async () => {
            const fetchFn = createFetchMock();

            fetchFn.mockResolvedValue(
                createFetchResponse({
                    ldhName: 'example.com',
                }),
            );

            const inspector = new RdapInspector({
                fetchFn: fetchFn as typeof fetch,
                baseUrl:
                    'https://rdap.example.test/domain',
            });

            await inspector.inspect(
                '  EXAMPLE.COM.  ',
            );

            expect(fetchFn).toHaveBeenCalledWith(
                'https://rdap.example.test/domain/example.com',
                expect.any(Object),
            );
        },
    );

    it(
        'devuelve valores nulos cuando la respuesta no contiene fechas o registrador',
        async () => {
            const fetchFn = createFetchMock();

            fetchFn.mockResolvedValue(
                createFetchResponse({
                    ldhName: 'example.com',
                    status: [],
                }),
            );

            const inspector = new RdapInspector({
                fetchFn: fetchFn as typeof fetch,
                baseUrl: 'https://rdap.example.test/domain',
            });

            const result = await inspector.inspect(
                'example.com',
            );

            expect(result).toEqual({
                domain: 'example.com',
                statuses: [],
                creationDate: null,
                expirationDate: null,
                updatedDate: null,
                registrar: null,
            });
        },
    );

    it(
        'utiliza unicodeName cuando ldhName no está disponible',
        async () => {
            const fetchFn = createFetchMock();

            fetchFn.mockResolvedValue(
                createFetchResponse({
                    unicodeName: 'example.com',
                }),
            );

            const inspector = new RdapInspector({
                fetchFn: fetchFn as typeof fetch,
                baseUrl: 'https://rdap.example.test/domain',
            });

            const result = await inspector.inspect(
                'example.com',
            );

            expect(result.domain).toBe(
                'example.com',
            );
        },
    );

    it(
        'lanza un error cuando RDAP responde con un estado no exitoso',
        async () => {
            const fetchFn = createFetchMock();

            fetchFn.mockResolvedValue(
                createFetchResponse(
                    {},
                    {
                        ok: false,
                        status: 404,
                    },
                ),
            );

            const inspector = new RdapInspector({
                fetchFn: fetchFn as typeof fetch,
                baseUrl: 'https://rdap.example.test/domain',
            });

            await expect(
                inspector.inspect('example.com'),
            ).rejects.toThrow(
                'No fue posible consultar RDAP para example.com: HTTP 404',
            );
        },
    );

    it(
        'rechaza un dominio vacío',
        async () => {
            const fetchFn = createFetchMock();

            const inspector = new RdapInspector({
                fetchFn: fetchFn as typeof fetch,
                baseUrl: 'https://rdap.example.test/domain',
            });

            await expect(
                inspector.inspect('   '),
            ).rejects.toThrow(
                'El dominio es obligatorio para consultar RDAP',
            );

            expect(fetchFn).not.toHaveBeenCalled();
        },
    );

    it(
        'rechaza un dominio que no es una cadena de texto',
        async () => {
            const inspector = new RdapInspector({
                fetchFn:
                    createFetchMock() as typeof fetch,
            });

            await expect(
                inspector.inspect(
                    null as unknown as string,
                ),
            ).rejects.toThrow(
                'El dominio es obligatorio para consultar RDAP',
            );
        },
    );

    it(
        'devuelve null como registrador cuando la entidad no contiene un nombre válido',
        async () => {
            const fetchFn = createFetchMock();

            fetchFn.mockResolvedValue(
                createFetchResponse({
                    ldhName: 'example.com',
                    entities: [
                        {
                            roles: [
                                'registrar',
                            ],
                            vcardArray: [
                                'vcard',
                                [],
                            ],
                        },
                    ],
                }),
            );

            const inspector = new RdapInspector({
                fetchFn: fetchFn as typeof fetch,
                baseUrl: 'https://rdap.example.test/domain',
            });

            const result = await inspector.inspect(
                'example.com',
            );

            expect(result.registrar).toBeNull();
        },
    );

    it('usa el RDAP autoritativo de IANA y consulta el dominio registrable', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValueOnce(
            createFetchResponse({
                services: [[['com'], ['https://rdap.verisign.com/com/v1/']]],
            }),
        );
        fetchFn.mockResolvedValueOnce(
            createFetchResponse({
                ldhName: 'example.com',
                events: [{
                    eventAction: 'registration',
                    eventDate: '1995-08-14T04:00:00Z',
                }],
            }),
        );

        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
        });
        const result = await inspector.inspect('www.example.com');

        expect(fetchFn).toHaveBeenNthCalledWith(
            1,
            'https://data.iana.org/rdap/dns.json',
            expect.objectContaining({
                headers: { Accept: 'application/json' },
            }),
        );
        expect(fetchFn).toHaveBeenNthCalledWith(
            2,
            'https://rdap.verisign.com/com/v1/domain/example.com',
            expect.objectContaining({
                headers: {
                    Accept: 'application/rdap+json, application/json',
                },
            }),
        );
        expect(result.domain).toBe('example.com');
        expect(result.creationDate).toBe('1995-08-14T04:00:00Z');
    });

    it('prueba endpoints RDAP en orden y se detiene cuando uno funciona', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValueOnce(createFetchResponse({
            services: [[['com'], [
                'https://rdap.first.example',
                'https://rdap.second.example',
                'https://rdap.third.example',
            ]]],
        }));
        fetchFn.mockResolvedValueOnce(
            createFetchResponse({}, { ok: false, status: 503 }),
        );
        fetchFn.mockResolvedValueOnce(
            createFetchResponse({ ldhName: 'example.com' }),
        );
        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
        });

        const result = await inspector.inspect('example.com');

        expect(result.domain).toBe('example.com');
        expect(fetchFn).toHaveBeenCalledTimes(3);
        expect(fetchFn).toHaveBeenNthCalledWith(
            2,
            'https://rdap.first.example/domain/example.com',
            expect.any(Object),
        );
        expect(fetchFn).toHaveBeenNthCalledWith(
            3,
            'https://rdap.second.example/domain/example.com',
            expect.any(Object),
        );
    });

    it('usa WHOIS del registro cuando IANA no anuncia RDAP para el TLD', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValue(
            createFetchResponse({
                services: [[['com'], ['https://rdap.verisign.com/com/v1/']]],
            }),
        );

        const whoisCalls: Array<[string, string]> = [];
        const whoisQueryFn = async (server: string, query: string) => {
            whoisCalls.push([server, query]);

            if (server === 'whois.iana.org') {
                return 'domain: CO\nwhois: whois.registry.co\n';
            }

            return [
                'Domain Name: IUE.EDU.CO',
                'Creation Date: 1998-06-09T00:00:00.0Z',
                'Registry Expiry Date: 2029-12-31T23:59:59.0Z',
                'Updated Date: 2025-12-26T13:37:50.0Z',
                'Registrar: www.registrocolombia.co',
                'Domain Status: ok',
                '',
            ].join('\r\n');
        };

        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
            whoisQueryFn,
        });
        const result = await inspector.inspect('www.iue.edu.co');

        expect(whoisCalls).toEqual([
            ['whois.iana.org', 'co'],
            ['whois.registry.co', 'iue.edu.co'],
        ]);
        expect(result).toEqual({
            domain: 'iue.edu.co',
            statuses: ['ok'],
            creationDate: '1998-06-09T00:00:00.0Z',
            expirationDate: '2029-12-31T23:59:59.0Z',
            updatedDate: '2025-12-26T13:37:50.0Z',
            registrar: 'www.registrocolombia.co',
        });
    });

    it('recurre a WHOIS si el endpoint RDAP autoritativo rechaza la solicitud', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValueOnce(
            createFetchResponse({
                services: [[['com'], ['https://rdap.verisign.com/com/v1/']]],
            }),
        );
        fetchFn.mockResolvedValueOnce(
            createFetchResponse({}, { ok: false, status: 403 }),
        );

        const whoisQueryFn = async (server: string) =>
            server === 'whois.iana.org'
                ? 'domain: COM\nwhois: whois.verisign-grs.com\n'
                : [
                    'Domain Name: EXAMPLE.COM',
                    'Creation Date: 1995-08-14T04:00:00Z',
                    'Registry Expiry Date: 2026-08-13T04:00:00Z',
                    'Registrar: Example Registrar',
                    '',
                ].join('\r\n');

        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
            whoisQueryFn,
        });
        const result = await inspector.inspect('example.com');

        expect(result.registrar).toBe('Example Registrar');
        expect(result.creationDate).toBe('1995-08-14T04:00:00Z');
    });

    it.each([0, 1.5])(
        'rechaza un timeout que no es un entero positivo: %s',
        timeoutMs => {
            expect(
                () => new RdapInspector({ timeoutMs }),
            ).toThrow('timeoutMs debe ser un entero positivo.');
        },
    );

    it('rechaza un límite de respuesta WHOIS no positivo', () => {
        expect(
            () => new RdapInspector({ maxWhoisResponseBytes: 0 }),
        ).toThrow('maxWhoisResponseBytes debe ser un entero positivo.');
    });

    it('usa WHOIS cuando el bootstrap de IANA no tiene la estructura esperada', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValue(
            createFetchResponse({ services: 'estructura inválida' }),
        );
        const whoisResponses = [
            'domain: COM\nwhois: whois.registry.example\n',
            'Domain Name: EXAMPLE.COM\nDomain Status: active\n',
        ];
        const whoisQueryFn = async () => whoisResponses.shift() ?? '';

        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
            whoisQueryFn,
        });
        const result = await inspector.inspect('example.com');

        expect(result.domain).toBe('example.com');
        expect(result.statuses).toEqual(['active']);
    });

    it('rechaza una respuesta WHOIS que se refiere a otro dominio', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValue(
            createFetchResponse({ services: [] }),
        );
        const whoisQueryFn = async (server: string) => (
            server === 'whois.iana.org'
                ? 'whois: whois.registry.example\n'
                : 'Domain Name: other.example\n'
        );
        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
            whoisQueryFn,
        });

        await expect(
            inspector.inspect('example.com'),
        ).rejects.toThrow('fuera del dominio registrable example.com');
    });

    it('tolera una tarjeta vCard incompleta en la respuesta RDAP', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValue(
            createFetchResponse({
                ldhName: 'example.com',
                entities: [{
                    roles: ['registrar'],
                    vcardArray: ['vcard'],
                }],
            }),
        );
        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
            baseUrl: 'https://rdap.example.test/domain',
        });

        const result = await inspector.inspect('example.com');

        expect(result.registrar).toBeNull();
    });

    it('rechaza un servidor WHOIS inválido anunciado por IANA', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValue(createFetchResponse({ services: [] }));
        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
            whoisQueryFn: async () => 'domain: COM\nwhois: invalid_server\n',
        });

        await expect(inspector.inspect('example.com')).rejects.toThrow(
            'IANA WHOIS no devolvió un servidor de registro válido.',
        );
    });

    it('rechaza un registro WHOIS que no incluye el nombre de dominio', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValue(createFetchResponse({ services: [] }));
        let queryCount = 0;
        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
            whoisQueryFn: async () => {
                queryCount += 1;
                return queryCount === 1
                    ? 'whois: whois.registry.example\n'
                    : 'Registrar: Example Registrar\n';
            },
        });

        await expect(inspector.inspect('example.com')).rejects.toThrow(
            'no devolvió un registro para example.com',
        );
    });

    it('conserva el error del bootstrap IANA al fallar también WHOIS', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValue(createFetchResponse({}, { ok: false, status: 503 }));
        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
            whoisQueryFn: async () => { throw new Error('WHOIS no disponible'); },
        });

        await expect(inspector.inspect('example.com')).rejects.toThrow(
            'RDAP: IANA RDAP bootstrap respondió con HTTP 503. WHOIS: WHOIS no disponible',
        );
    });

    it.each([
        {
            scenario: 'un endpoint sin HTTPS',
            services: [[['com'], ['http://rdap.inseguro.example']]],
        },
        {
            scenario: 'una URL de endpoint mal formada',
            services: [[['com'], ['https://[invalid']]],
        },
        {
            scenario: 'un TLD diferente',
            services: [[['org'], ['https://rdap.example.org']]],
        },
    ])('recurre a WHOIS cuando el bootstrap contiene $scenario', async ({ services }) => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValue(createFetchResponse({ services }));
        const replies = [
            'whois: whois.registry.example\n',
            'Domain Name: EXAMPLE.COM\n',
        ];
        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
            whoisQueryFn: async () => replies.shift() ?? '',
        });

        const result = await inspector.inspect('example.com');

        expect(result.domain).toBe('example.com');
        expect(fetchFn).toHaveBeenCalledTimes(1);
    });

    it('rechaza nombres sin un dominio registrable antes de consultar fuentes externas', async () => {
        const fetchFn = createFetchMock();
        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
        });

        await expect(inspector.inspect('localhost')).rejects.toThrow(
            'No fue posible identificar el dominio registrable de localhost.',
        );
        expect(fetchFn).not.toHaveBeenCalled();
    });

    it('puede construirse con la configuración RDAP predeterminada sin consultar la red', () => {
        expect(() => new RdapInspector()).not.toThrow();
    });

    it('devuelve el dominio normalizado cuando RDAP no incluye nombres', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValue(createFetchResponse({
            status: ['active'],
        }));
        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
            baseUrl: 'https://rdap.example.test/domain',
        });

        const result = await inspector.inspect('example.com');

        expect(result.domain).toBe('example.com');
    });

    it('salta propiedades vCard inválidas hasta encontrar el nombre del registrador', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValue(createFetchResponse({
            ldhName: 'example.com',
            entities: [{
                roles: ['registrar'],
                vcardArray: [
                    'vcard',
                    [null, ['fn'], ['fn', {}, 'text', 'Example Registrar']],
                ],
            }],
        }));
        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
            baseUrl: 'https://rdap.example.test/domain',
        });

        const result = await inspector.inspect('example.com');

        expect(result.registrar).toBe('Example Registrar');
    });

    it('tolera entidades registradoras sin tarjeta vCard', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValue(createFetchResponse({
            ldhName: 'example.com',
            entities: [{ roles: ['registrar'] }],
        }));
        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
            baseUrl: 'https://rdap.example.test/domain',
        });

        const result = await inspector.inspect('example.com');

        expect(result.registrar).toBeNull();
    });

    it('recurre a WHOIS cuando el bootstrap no incluye la lista services', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockResolvedValue(createFetchResponse({}));
        const replies = [
            'whois: whois.registry.example\n',
            'Domain Name: EXAMPLE.COM\n',
        ];
        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
            whoisQueryFn: async () => replies.shift() ?? '',
        });

        const result = await inspector.inspect('example.com');

        expect(result.domain).toBe('example.com');
        expect(fetchFn).toHaveBeenCalledTimes(1);
    });

    it('formatea errores no estándar recibidos del bootstrap y WHOIS', async () => {
        const fetchFn = createFetchMock();
        fetchFn.mockRejectedValue('bootstrap offline');
        const inspector = new RdapInspector({
            fetchFn: fetchFn as typeof fetch,
            whoisQueryFn: async () => Promise.reject('WHOIS offline'),
        });

        await expect(inspector.inspect('example.com')).rejects.toThrow(
            'RDAP: bootstrap offline WHOIS: WHOIS offline',
        );
    });
});

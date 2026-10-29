import dotenv from 'dotenv';

dotenv.config({ quiet: true });

export interface WorkerConfig {
nodeEnv: 'development' | 'test' | 'production';
logLevel: 'fatal' | 'error' | 'warn' | 'info' | 'debug' | 'trace' | 'silent';
database: {
host: string;
port: number;
name: string;
user: string;
password: string;
};
worker: {
pollIntervalMs: number;
batchSize: number;
};
virusTotalApiKey?: string;
}

function requiredString(name: string): string {
const value = process.env[name]?.trim();

if (!value) {
throw new Error(`La variable de entorno ${name} es obligatoria.`);
}

return value;
}

function positiveInteger(name: string, defaultValue: number): number {
const rawValue = process.env[name];

if (rawValue === undefined || rawValue.trim() === '') {
return defaultValue;
}

const value = Number(rawValue);

if (!Number.isSafeInteger(value) || value <= 0) {
throw new Error(
`La variable ${name} debe ser un número entero positivo.`,
);
}

return value;
}

function optionalString(name: string): string | undefined {
const value = process.env[name]?.trim();

return value || undefined;
}

function parseLogLevel(): WorkerConfig['logLevel'] {
const value = process.env.LOG_LEVEL?.trim() || 'info';

const validLevels: WorkerConfig['logLevel'][] = [
'fatal',
'error',
'warn',
'info',
'debug',
'trace',
'silent',
];

if (!validLevels.includes(value as WorkerConfig['logLevel'])) {
throw new Error(
`LOG_LEVEL debe ser uno de los siguientes valores: ${validLevels.join(', ')}.`,
);
}

return value as WorkerConfig['logLevel'];
}

function parseNodeEnvironment(): WorkerConfig['nodeEnv'] {
const value = process.env.NODE_ENV?.trim() || 'development';

const validEnvironments: WorkerConfig['nodeEnv'][] = [
'development',
'test',
'production',
];

if (!validEnvironments.includes(value as WorkerConfig['nodeEnv'])) {
throw new Error(
'NODE_ENV debe ser development, test o production.',
);
}

return value as WorkerConfig['nodeEnv'];
}

export function loadConfig(): WorkerConfig {
const dbPort = positiveInteger('DB_PORT', 3308);

if (dbPort > 65535) {
throw new Error('DB_PORT debe estar entre 1 y 65535.');
}

const virusTotalApiKey = optionalString('VIRUSTOTAL_API_KEY');

return {
nodeEnv: parseNodeEnvironment(),
logLevel: parseLogLevel(),
database: {
host: requiredString('DB_HOST'),
port: dbPort,
name: requiredString('DB_NAME'),
user: requiredString('DB_USER'),
password: requiredString('DB_PASSWORD'),
},
worker: {
pollIntervalMs: positiveInteger(
'WORKER_POLL_INTERVAL_MS',
5000,
),
batchSize: positiveInteger('WORKER_BATCH_SIZE', 1),
},
...(virusTotalApiKey ? { virusTotalApiKey } : {}),
};
}

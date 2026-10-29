import pino from 'pino';

const logger = pino({
level: process.env.LOG_LEVEL ?? 'info',
});

function main(): void {
logger.info('CyberScore Worker iniciado correctamente.');
}

main();

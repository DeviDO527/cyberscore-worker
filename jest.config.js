/** @type {import('jest').Config} */
module.exports = {
preset: 'ts-jest',
testEnvironment: 'node',
testMatch: ['<rootDir>/test/**/*.test.ts'],
clearMocks: true,
collectCoverageFrom: ['src/**/*.ts'],
coverageDirectory: 'coverage',
coveragePathIgnorePatterns: ['/node_modules/', '/dist/'],
};

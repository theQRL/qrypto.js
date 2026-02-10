/* eslint-disable */
module.exports = function () {
  return {
    env: {
      type: 'node',
      runner: 'node',
    },
    workers: { restart: true },
    files: [
      { pattern: 'package.json', instrument: false },
      { pattern: 'packages/dilithium5/package.json', instrument: false },
      'packages/dilithium5/src/**/*.js',
      { pattern: 'packages/dilithium5/dist/**/*.js', instrument: false },
      { pattern: 'packages/dilithium5/dist/**/package.json', instrument: false },
    ],
    tests: ['packages/dilithium5/test/**/*.js'],
    testFramework: 'mocha',
  };
};

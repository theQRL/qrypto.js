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
      { pattern: 'packages/mldsa87/package.json', instrument: false },
      'packages/mldsa87/src/**/*.js',
      { pattern: 'packages/mldsa87/dist/**/*.js', instrument: false },
      { pattern: 'packages/mldsa87/dist/**/package.json', instrument: false },
    ],
    tests: ['packages/mldsa87/test/**/*.js'],
    testFramework: 'mocha',
  };
};

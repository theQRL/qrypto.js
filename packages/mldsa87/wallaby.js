/* eslint-disable */
module.exports = function (wallaby) {
  return {
    env: {
      type: 'node',
      runner: 'node',
    },
    files: ['src/**/*.js'],
    tests: ['test/**/*.js'],
    testFramework: 'mocha',
  };
};

/* eslint-disable */
module.exports = function (wallaby) {
  return {
    env: {
      type: 'node',
      runner: 'node',
      params: {
        runner: `-r ${require.resolve('esm')}`,
      }
    },
    files: ['src/**/*.js'],
    tests: ['test/**/*.js'],
    testFramework: 'mocha',
  };
};

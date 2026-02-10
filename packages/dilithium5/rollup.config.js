/**
 * Rollup configuration for dual ESM/CJS builds.
 *
 * @noble/hashes is ESM-only, so it must be bundled into the CJS build
 * to avoid ERR_REQUIRE_ESM at runtime.
 */
import resolve from '@rollup/plugin-node-resolve';

const nobleExternal = ['@noble/hashes/sha3.js', '@noble/hashes/utils.js'];

export default [
  {
    input: 'src/index.js',
    output: {
      file: 'dist/cjs/dilithium5.js',
      format: 'cjs',
      exports: 'named',
    },
    plugins: [resolve({ preferBuiltins: false })],
    // Bundle @noble/hashes into CJS since it is ESM-only
    external: [],
  },
  {
    input: 'src/index.js',
    output: {
      file: 'dist/mjs/dilithium5.js',
      format: 'esm',
    },
    external: nobleExternal,
  },
];

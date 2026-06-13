import js from '@eslint/js';
import importX from 'eslint-plugin-import-x';
import prettier from 'eslint-plugin-prettier';
import prettierConfig from 'eslint-config-prettier';
import globals from 'globals';

// House rule deltas — crypto/reference-port code legitimately needs what
// generic style guides ban. Defined once and shared by every JS/MJS block so
// the rules cannot drift between the source and the tooling that guards it.
const houseRules = {
  'prettier/prettier': 'error',
  'import-x/extensions': ['error', 'ignorePackages'],
  'import-x/namespace': 'off', // parsing issues with TS deps in node_modules
  'max-classes-per-file': 'off',
  'no-bitwise': 'off',
  'no-plusplus': 'off',
  'no-param-reassign': 'off',
  'no-continue': 'off',
  'no-constant-condition': 'off',
  'no-shadow': 'off',
  'prefer-destructuring': 'off',
  'no-use-before-define': ['error', { functions: false }],
};

export default [
  // Lint EVERYTHING executable, not just src/test. The fuzz engine + 8
  // harnesses, the release tooling, browser-test shims, and the cross-verify
  // JS are all code that can carry bugs — `eslint .` covers them in one pass.
  // Excluded: build output, vendored/committed artifacts, generated typings
  // (checked by `npm run typecheck`), Go modules, and non-JS files.
  {
    ignores: [
      '**/node_modules/**',
      '**/dist/**',
      '**/coverage/**',
      '**/*.lcov',
      'fuzz-results/**',
      '**/fuzz/corpus/**',
      '**/*.d.ts',
      '**/*.d.mts',
      '**/*.d.cts',
      'test/types/**', // TypeScript consumer-compile fixtures — `npm run typecheck`
      '.github/cross-verify/*-go/**', // Go modules
      '**/*.html',
      '**/wallaby*.js', // local dev test-runner config, not shipped
      '**/wallaby*.cjs',
    ],
  },

  js.configs.recommended,
  importX.flatConfigs.recommended,
  prettierConfig,

  // Crypto source + unit tests (ES2020 target, matching the build).
  {
    files: ['packages/*/src/**/*.js', 'packages/*/test/**/*.js'],
    plugins: { prettier },
    languageOptions: {
      ecmaVersion: 2020,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.node,
        ...globals.mocha,
        ...globals.es2020,
      },
    },
    rules: houseRules,
  },

  // Tooling: fuzz engine + harnesses, release/check scripts, cross-verify
  // signers/verifiers, and the config files themselves. Node ESM.
  {
    files: [
      'scripts/**/*.js',
      'scripts/**/*.mjs',
      'packages/*/fuzz/**/*.mjs',
      '.github/cross-verify/**/*.js',
      'packages/*/playwright.config.js',
      'eslint.config.js',
    ],
    plugins: { prettier },
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.node,
        ...globals.es2021,
      },
    },
    rules: houseRules,
  },

  // Browser-test shims + specs run in Chromium via Playwright; they touch
  // browser globals and the mocha globals the shim re-exports.
  {
    files: ['packages/*/browser-tests/**/*.js'],
    plugins: { prettier },
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        ...globals.mocha,
        ...globals.node,
        ...globals.es2021,
      },
    },
    rules: houseRules,
  },

  // CommonJS helpers (node test setup shim).
  {
    files: ['**/*.cjs'],
    plugins: { prettier },
    languageOptions: {
      ecmaVersion: 2022,
      sourceType: 'commonjs',
      globals: { ...globals.node },
    },
    rules: {
      'prettier/prettier': 'error',
    },
  },

  // This config file uses the documented `import importX from
  // 'eslint-plugin-import-x'; importX.flatConfigs.recommended` pattern; the
  // default-vs-named warnings are false positives for that intended usage.
  {
    files: ['eslint.config.js'],
    rules: {
      'import-x/no-named-as-default': 'off',
      'import-x/no-named-as-default-member': 'off',
    },
  },
];

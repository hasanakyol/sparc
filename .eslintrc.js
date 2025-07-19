module.exports = {
  root: true,
  env: {
    browser: true,
    es2022: true,
    node: true,
  },
  extends: [
    'eslint:recommended',
    '@typescript-eslint/recommended',
    '@typescript-eslint/recommended-requiring-type-checking',
    'plugin:security/recommended',
    'plugin:import/recommended',
    'plugin:import/typescript',
    'prettier',
  ],
  parser: '@typescript-eslint/parser',
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
    project: ['./tsconfig.json', './web/tsconfig.json', './services/*/tsconfig.json', './packages/*/tsconfig.json'],
    tsconfigRootDir: __dirname,
  },
  plugins: [
    '@typescript-eslint',
    'security',
    'import',
    'unused-imports',
  ],
  settings: {
    'import/resolver': {
      typescript: {
        alwaysTryTypes: true,
        project: ['./tsconfig.json', './web/tsconfig.json', './services/*/tsconfig.json', './packages/*/tsconfig.json'],
      },
    },
  },
  rules: {
    // TypeScript specific rules
    '@typescript-eslint/no-unused-vars': 'error',
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/explicit-module-boundary-types': 'off',
    '@typescript-eslint/no-non-null-assertion': 'warn',
    '@typescript-eslint/prefer-nullish-coalescing': 'error',
    '@typescript-eslint/prefer-optional-chain': 'error',
    '@typescript-eslint/no-floating-promises': 'error',
    '@typescript-eslint/await-thenable': 'error',
    '@typescript-eslint/no-misused-promises': 'error',
    '@typescript-eslint/require-await': 'error',
    '@typescript-eslint/no-unnecessary-type-assertion': 'error',
    '@typescript-eslint/prefer-as-const': 'error',
    '@typescript-eslint/consistent-type-imports': ['error', { prefer: 'type-imports' }],
    '@typescript-eslint/consistent-type-definitions': ['error', 'interface'],

    // Import organization rules
    'import/order': [
      'error',
      {
        groups: [
          'builtin',
          'external',
          'internal',
          'parent',
          'sibling',
          'index',
          'type',
        ],
        'newlines-between': 'always',
        alphabetize: {
          order: 'asc',
          caseInsensitive: true,
        },
        pathGroups: [
          {
            pattern: '@sparc/**',
            group: 'internal',
            position: 'before',
          },
        ],
        pathGroupsExcludedImportTypes: ['builtin'],
      },
    ],
    'import/no-unresolved': 'error',
    'import/no-cycle': 'error',
    'import/no-self-import': 'error',
    'import/no-useless-path-segments': 'error',
    'import/no-duplicates': 'error',
    'import/first': 'error',
    'import/newline-after-import': 'error',
    'import/no-default-export': 'off', // Allow default exports for Next.js pages and components

    // Unused imports
    'unused-imports/no-unused-imports': 'error',
    'unused-imports/no-unused-vars': [
      'warn',
      {
        vars: 'all',
        varsIgnorePattern: '^_',
        args: 'after-used',
        argsIgnorePattern: '^_',
      },
    ],

    // Security rules
    'security/detect-object-injection': 'warn',
    'security/detect-non-literal-regexp': 'warn',
    'security/detect-unsafe-regex': 'error',
    'security/detect-buffer-noassert': 'error',
    'security/detect-child-process': 'warn',
    'security/detect-disable-mustache-escape': 'error',
    'security/detect-eval-with-expression': 'error',
    'security/detect-no-csrf-before-method-override': 'error',
    'security/detect-non-literal-fs-filename': 'warn',
    'security/detect-non-literal-require': 'warn',
    'security/detect-possible-timing-attacks': 'warn',
    'security/detect-pseudoRandomBytes': 'error',

    // General code quality rules
    'no-console': 'warn',
    'no-debugger': 'error',
    'no-alert': 'error',
    'no-var': 'error',
    'prefer-const': 'error',
    'prefer-arrow-callback': 'error',
    'arrow-spacing': 'error',
    'no-duplicate-imports': 'error',
    'no-useless-rename': 'error',
    'object-shorthand': 'error',
    'prefer-destructuring': ['error', { object: true, array: false }],
    'prefer-template': 'error',
    'template-curly-spacing': 'error',
    'no-nested-ternary': 'error',
    'no-unneeded-ternary': 'error',
    'spaced-comment': ['error', 'always'],

    // Naming conventions
    '@typescript-eslint/naming-convention': [
      'error',
      {
        selector: 'default',
        format: ['camelCase'],
      },
      {
        selector: 'variable',
        format: ['camelCase', 'UPPER_CASE', 'PascalCase'],
      },
      {
        selector: 'parameter',
        format: ['camelCase'],
        leadingUnderscore: 'allow',
      },
      {
        selector: 'memberLike',
        modifiers: ['private'],
        format: ['camelCase'],
        leadingUnderscore: 'require',
      },
      {
        selector: 'typeLike',
        format: ['PascalCase'],
      },
      {
        selector: 'property',
        format: ['camelCase', 'snake_case', 'UPPER_CASE'],
      },
      {
        selector: 'enumMember',
        format: ['UPPER_CASE'],
      },
      {
        selector: 'interface',
        format: ['PascalCase'],
        custom: {
          regex: '^I[A-Z]',
          match: false,
        },
      },
    ],

    // Performance considerations
    'no-await-in-loop': 'warn',
    'prefer-promise-reject-errors': 'error',
  },
  overrides: [
    // React/Next.js specific rules for web directory
    {
      files: ['web/**/*.{ts,tsx}'],
      extends: [
        'plugin:react/recommended',
        'plugin:react-hooks/recommended',
        'plugin:jsx-a11y/recommended',
        'plugin:@next/next/recommended',
      ],
      plugins: ['react', 'react-hooks', 'jsx-a11y'],
      settings: {
        react: {
          version: 'detect',
        },
      },
      rules: {
        'react/react-in-jsx-scope': 'off', // Not needed in Next.js 13+
        'react/prop-types': 'off', // Using TypeScript for prop validation
        'react/display-name': 'off',
        'react/no-unescaped-entities': 'off',
        'react/jsx-key': 'error',
        'react/jsx-no-duplicate-props': 'error',
        'react/jsx-no-undef': 'error',
        'react/jsx-uses-react': 'off', // Not needed in Next.js 13+
        'react/jsx-uses-vars': 'error',
        'react/no-deprecated': 'error',
        'react/no-direct-mutation-state': 'error',
        'react/no-unknown-property': 'error',
        'react/require-render-return': 'error',
        'react/self-closing-comp': 'error',
        'react/jsx-boolean-value': ['error', 'never'],
        'react/jsx-curly-brace-presence': ['error', { props: 'never', children: 'never' }],
        'react/jsx-fragments': ['error', 'syntax'],
        'react/jsx-no-useless-fragment': 'error',
        'react/jsx-pascal-case': 'error',
        'react/jsx-sort-props': [
          'error',
          {
            callbacksLast: true,
            shorthandFirst: true,
            multiline: 'last',
            reservedFirst: true,
          },
        ],
        'react-hooks/rules-of-hooks': 'error',
        'react-hooks/exhaustive-deps': 'warn',
        'jsx-a11y/alt-text': 'error',
        'jsx-a11y/anchor-has-content': 'error',
        'jsx-a11y/anchor-is-valid': 'error',
        'jsx-a11y/click-events-have-key-events': 'warn',
        'jsx-a11y/no-static-element-interactions': 'warn',
        'import/no-default-export': 'off', // Allow default exports for Next.js pages and components
      },
    },
    // Node.js specific rules for services
    {
      files: ['services/**/*.ts', 'packages/**/*.ts'],
      env: {
        node: true,
        browser: false,
      },
      rules: {
        'no-console': 'off', // Allow console in backend services for logging
        'import/no-default-export': 'error', // Prefer named exports in backend
        'security/detect-non-literal-fs-filename': 'error',
        'security/detect-child-process': 'error',
      },
    },
    // Configuration files
    {
      files: ['*.config.{js,ts}', '*.rc.{js,ts}', '.eslintrc.js'],
      rules: {
        'import/no-default-export': 'off',
        '@typescript-eslint/no-var-requires': 'off',
      },
    },
    // Test files
    {
      files: ['**/*.test.{ts,tsx}', '**/*.spec.{ts,tsx}', '**/__tests__/**/*.{ts,tsx}'],
      extends: ['plugin:jest/recommended'],
      plugins: ['jest'],
      env: {
        jest: true,
      },
      rules: {
        '@typescript-eslint/no-explicit-any': 'off',
        '@typescript-eslint/no-non-null-assertion': 'off',
        'security/detect-object-injection': 'off',
        'import/no-default-export': 'off',
      },
    },
    // Infrastructure files
    {
      files: ['infra/**/*.ts'],
      rules: {
        'import/no-default-export': 'off', // CDK stacks use default exports
        '@typescript-eslint/no-explicit-any': 'off', // CDK props can be any
      },
    },
    // Scripts
    {
      files: ['scripts/**/*.{js,ts}'],
      rules: {
        'no-console': 'off',
        'import/no-default-export': 'off',
        '@typescript-eslint/no-var-requires': 'off',
      },
    },
  ],
  ignorePatterns: [
    'node_modules/',
    'dist/',
    'build/',
    '.next/',
    'coverage/',
    '*.min.js',
    'cdk.out/',
    '.aws-sam/',
    'prisma/migrations/',
  ],
};

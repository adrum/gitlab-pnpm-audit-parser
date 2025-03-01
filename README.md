# GitLab parser for PNPM Audit

```
Usage: gitlab-pnpm-audit-parser [options]

Options:

  -V, --version     output the version number
  -o, --out <path>  output filename, defaults to gl-dependency-scanning-report.json
  -h, --help        output usage information
```

## How to use

Install this package.

```
npm install --save-dev gitlab-pnpm-audit-parser
```

Add the following job to _.gitlab-ci.yml_

```yaml
dependency scanning:
  image: node:20-alpine
  before_script:
    - npm i -g corepack@latest
    - corepack enable
    - corepack prepare pnpm@latest-9 --activate
    - pnpm config set store-dir .pnpm-store
  script:
    - pnpm i
    - pnpm audit --format=json | npx gitlab-pnpm-audit-parser -o gl-dependency-scanning.json
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning.json
```

NOTE: If you use a `npm run-script` to call `npm audit` You must add the option `--silent` to `npm run` or have `.npmrc` set the NPM loglevel to silent otherwise the shell output will conflict with the stdin piping to this parser and cause an error.

## Test

`cat test/juice-shop.json | ./parse.js -o report.json`

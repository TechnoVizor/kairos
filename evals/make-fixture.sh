#!/usr/bin/env bash
# Builds a small Node/Express repo with KNOWN, seeded weaknesses (list: evals/README.md, scenario 1).
# It is generated on demand so that no scannable fake secret is ever stored in the kairos repo.
# Never push the result anywhere.
#
# Usage: bash make-fixture.sh [dir]
#   dir  default ~/.cache/kairos-eval/seeded-app (must be under $HOME so Docker can mount it)
# Needs: git, npm (network, only to create the lockfile).
set -euo pipefail

DIR=${1:-$HOME/.cache/kairos-eval/seeded-app}
rm -rf "$DIR"; mkdir -p "$DIR"/{lib,test,config,.github/workflows}; cd "$DIR"
git init -q -b main
git config user.name "Eval Fixture"; git config user.email "fixture@example.invalid"

# A fake key in Stripe's live-key format, assembled at runtime.
FAKE="sk_""live_""Xq7ZrP2mVb9LkT4nWc8HsJdF"

cat > package.json <<'EOF'
{
  "name": "acme-notes",
  "version": "1.0.0",
  "private": true,
  "scripts": { "start": "node server.js", "test": "node --test" },
  "dependencies": { "express": "4.17.1", "lodash": "4.17.10" }
}
EOF
npm install --package-lock-only --ignore-scripts --no-audit --no-fund >/dev/null 2>&1

cat > server.js <<'EOF'
const express = require('express');
const _ = require('lodash');
const { exec } = require('child_process');
const { title } = require('./lib/format');

const JWT_SECRET = 'supersecret123';
const app = express();
app.use(express.json());

const users = new Map([['1', { name: 'alice' }], ['2', { name: 'bob' }]]);
const defaults = { theme: 'light' };

// any request that carries an x-user header counts as logged in
const requireLogin = (req, res, next) => (req.headers['x-user'] ? next() : res.status(401).end());

app.get('/hello', (req, res) => res.send(`<h1>Hello ${title(req.query.name || 'world')}</h1>`));
app.get('/ping', (req, res) => exec(`ping -c1 ${req.query.host}`, (err, out) => res.send(out)));
app.post('/settings', requireLogin, (req, res) => res.json(_.merge({}, defaults, req.body)));
app.delete('/admin/users/:id', requireLogin, (req, res) => {
  users.delete(req.params.id);
  res.json({ ok: true });
});

if (require.main === module) app.listen(3000);
module.exports = { app, JWT_SECRET };
EOF

cat > lib/format.js <<'EOF'
exports.title = (s) => s.charAt(0).toUpperCase() + s.slice(1);
exports.slug = (s) => s.toLowerCase().replace(/\s+/g, '-');
EOF

cat > test/format.test.js <<'EOF'
const test = require('node:test');
const assert = require('node:assert');
const { title } = require('../lib/format');

test('title capitalizes', () => assert.equal(title('note'), 'Note'));
EOF

cat > Dockerfile <<'EOF'
FROM node:14
WORKDIR /app
COPY . .
RUN npm install
CMD ["node", "server.js"]
EOF

cat > .env <<'EOF'
DATABASE_URL=postgres://admin:hunter2@db.internal:5432/notes
SESSION_SECRET=change-me
EOF

cat > .github/workflows/ci.yml <<'EOF'
name: CI
on:
  pull_request_target:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - name: Greet
        run: echo "Testing PR ${{ github.event.pull_request.title }}"
      - uses: actions/setup-node@main
      - run: npm ci && npm test
EOF

printf 'node_modules/\n' > .gitignore
printf '# Acme Notes\n\nA tiny notes API.\n' > README.md

cat > config/payments.js <<EOF
module.exports = { stripeKey: '$FAKE' };
EOF

git add -A && git commit -q -m "Initial version of the notes API"

cat > config/payments.js <<'EOF'
module.exports = { stripeKey: process.env.STRIPE_KEY };
EOF
git add -A && git commit -q -m "Read the payment key from the environment"

echo "fixture ready: $DIR ($(git rev-list --count HEAD) commits)"

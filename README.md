# Pick a QUIC Codepoint

https://martinthomson.github.io/quic-pick/

## Programmatic use

The selection algorithm is available as an ES module (`quic-pick.js`) for
use in build tooling and scripts, without needing a browser.

### Browser

Serve the files over HTTPS (module imports don't work over `file://`) and
import in a `<script type="module">`:

```html
<script type="module">
  import { pick } from './quic-pick.js';
  const codepoint = await pick({ seed: 'draft-foo-bar-01', field: 'frame', bytes: 8 });
</script>
```

### Node.js

Node 18+ has a global `fetch`, so no extra setup is needed:

```js
import { pick } from './quic-pick.js';
const codepoint = await pick({ seed: 'draft-foo-bar-01', field: 'frame', bytes: 8 });
```

For older Node versions, pass a `fetchFn`:

```js
import https from 'https';

function fetchFn(url) {
  return new Promise((resolve, reject) => {
    https.get(url, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ text: async () => data }));
    }).on('error', reject);
  });
}

const codepoint = await pick({ seed: 'draft-foo-bar-01', field: 'frame', bytes: 8, fetchFn });
```

### Tests

```sh
node test.mjs
```

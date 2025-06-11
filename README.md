# xchacha-poly

Encrypt and decrypt, with authentication and additional data
([RFC 8439](https://rfc-editor.org/rfc/rfc8439)).

```ts
import { decrypt, encrypt } from "@nyoon/xchacha-poly";
import { assertEquals } from "jsr:@std/assert@^1.0.13";

const key = crypto.getRandomValues(new Uint8Array(32));
const text = new TextEncoder().encode("secret plaintext");
assertEquals(decrypt(key, encrypt(key, text)), text);

const data = new TextEncoder().encode("additional associated data");
assertEquals(decrypt(key, encrypt(key, text, data), data), text);
```

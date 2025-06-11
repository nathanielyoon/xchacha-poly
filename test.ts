import { hex } from "jsr:@nyoon/base@^2.0.0";
import { assertEquals } from "jsr:@std/assert@^1.0.13";
import { polyxchacha, xchachapoly } from "./mod.ts";

Deno.test("wycheproof", () =>
  fetch(
    "https://raw.githubusercontent.com/C2SP/wycheproof/f3071a24598bd87d09cd592dbe9fe2516d385590/testvectors_v1/xchacha20_poly1305_test.json",
  ).then<{ testGroups: { tests: Record<string, string>[] }[] }>(($) => $.json())
    .then(({ testGroups }) =>
      testGroups.forEach(({ tests }) =>
        tests.forEach(($) => {
          const a = ["key", "iv", "msg", "aad"].map((key) => hex($[key]));
          const b = hex($.ct + $.tag);
          $.result === "valid"
            ? assertEquals(xchachapoly(a[0], a[1], a[2], a[3]), b)
            : assertEquals(polyxchacha(a[0], a[1], b, a[2]), null);
        })
      )
    ));
Deno.test("invalid", () => {
  const a = new Uint8Array();
  for (const b of [xchachapoly, polyxchacha]) {
    assertEquals(b(a, new Uint8Array(48), a, a), null);
    assertEquals(b(new Uint8Array(64), a, a, a), null);
  }
});

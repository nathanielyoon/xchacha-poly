import { assertEquals } from "@std/assert";
import { poly_xchacha, xchacha_poly } from "../main.ts";
import vectors from "./vectors.json" with { type: "json" };

const s16_b = (hex: string) =>
  Uint8Array.from(hex.match(/../g) ?? [], (Z) => parseInt(Z, 16));
Deno.test(function xchacha20_poly1305() {
  for (let z = 0; z < vectors.testGroups.length; ++z) {
    const a = vectors.testGroups[z].tests;
    for (let y = 0; y < a.length; ++y) {
      const b = a[y], c = s16_b(b.key), d = s16_b(b.iv);
      const e = s16_b(b.ct + b.tag), f = s16_b(b.aad);
      if (b.result === "valid") {
        const g = s16_b(b.msg), h = xchacha_poly(c, d, g, f);
        assertEquals(h.subarray(0, -16), s16_b(b.ct));
        assertEquals(h.subarray(-16), s16_b(b.tag));
        assertEquals(poly_xchacha(c, d, e, f), g);
      } else assertEquals(poly_xchacha(c, d, e, f), false);
    }
  }
});

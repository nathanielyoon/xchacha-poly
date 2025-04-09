const A = 0x61707865, B = 0x3320646e, C = 0x79622d32, D = 0x6b206574;
/** Runs a {@link https://w.wiki/8NMF | ChaCha20} block. */
export const chacha = (
  key: DataView,
  counter: number,
  iv_0: number,
  iv_1: number,
  iv_2: number,
  to: Uint32Array,
) => {
  const a = key.getUint32(0, true), b = key.getUint32(4, true);
  const c = key.getUint32(8, true), d = key.getUint32(12, true);
  const e = key.getUint32(16, true), f = key.getUint32(20, true);
  const g = key.getUint32(24, true), h = key.getUint32(28, true);
  let i = A, j = B, k = C, l = D, m = a, n = b, o = c, p = d, q = e, r = f;
  let s = g, t = h, u = counter, v = iv_0, w = iv_1, x = iv_2, z = 10;
  do u ^= i = i + m | 0,
    u = u << 16 | u >>> 16,
    m ^= q = q + u | 0,
    m = m << 12 | m >>> 20,
    u ^= i = i + m | 0,
    u = u << 8 | u >>> 24,
    m ^= q = q + u | 0,
    m = m << 7 | m >>> 25,
    v ^= j = j + n | 0,
    v = v << 16 | v >>> 16,
    n ^= r = r + v | 0,
    n = n << 12 | n >>> 20,
    v ^= j = j + n | 0,
    v = v << 8 | v >>> 24,
    n ^= r = r + v | 0,
    n = n << 7 | n >>> 25,
    w ^= k = k + o | 0,
    w = w << 16 | w >>> 16,
    o ^= s = s + w | 0,
    o = o << 12 | o >>> 20,
    w ^= k = k + o | 0,
    w = w << 8 | w >>> 24,
    o ^= s = s + w | 0,
    o = o << 7 | o >>> 25,
    x ^= l = l + p | 0,
    x = x << 16 | x >>> 16,
    p ^= t = t + x | 0,
    p = p << 12 | p >>> 20,
    x ^= l = l + p | 0,
    x = x << 8 | x >>> 24,
    p ^= t = t + x | 0,
    p = p << 7 | p >>> 25,
    x ^= i = i + n | 0,
    x = x << 16 | x >>> 16,
    n ^= s = s + x | 0,
    n = n << 12 | n >>> 20,
    x ^= i = i + n | 0,
    x = x << 8 | x >>> 24,
    n ^= s = s + x | 0,
    n = n << 7 | n >>> 25,
    u ^= j = j + o | 0,
    u = u << 16 | u >>> 16,
    o ^= t = t + u | 0,
    o = o << 12 | o >>> 20,
    u ^= j = j + o | 0,
    u = u << 8 | u >>> 24,
    o ^= t = t + u | 0,
    o = o << 7 | o >>> 25,
    v ^= k = k + p | 0,
    v = v << 16 | v >>> 16,
    p ^= q = q + v | 0,
    p = p << 12 | p >>> 20,
    v ^= k = k + p | 0,
    v = v << 8 | v >>> 24,
    p ^= q = q + v | 0,
    p = p << 7 | p >>> 25,
    w ^= l = l + m | 0,
    w = w << 16 | w >>> 16,
    m ^= r = r + w | 0,
    m = m << 12 | m >>> 20,
    w ^= l = l + m | 0,
    w = w << 8 | w >>> 24,
    m ^= r = r + w | 0,
    m = m << 7 | m >>> 25; while (--z);
  to[0] = A + i, to[1] = B + j, to[2] = C + k, to[3] = D + l, to[4] = a + m;
  to[5] = b + n, to[6] = c + o, to[7] = d + p, to[8] = e + q, to[9] = f + r;
  to[10] = g + s, to[11] = h + t, to[12] = counter + u, to[13] = iv_0 + v;
  to[14] = iv_1 + w, to[15] = iv_2 + x;
};
/** Derives a subkey from a {@link key} and {@link iv | IV}. */
const hchacha = (use: Uint32Array, key: DataView, iv: DataView) => {
  const a = new DataView(new ArrayBuffer(32));
  const b = iv.getUint32(0, true), c = iv.getUint32(4, true);
  const d = iv.getUint32(8, true), e = iv.getUint32(12, true);
  chacha(key, b, c, d, e, use), a.setUint32(0, use[0] - A, true);
  a.setUint32(4, use[1] - B, true), a.setUint32(8, use[2] - C, true);
  a.setUint32(12, use[3] - D, true), a.setUint32(16, use[12] - b, true);
  a.setUint32(20, use[13] - c, true), a.setUint32(24, use[14] - d, true);
  return a.setUint32(28, use[15] - e, true), a;
};
const E = 0xffff, F = 0x1fff;
/** Computes an authentication tag for a well-constructed {@link message}. */
export const poly = (key: DataView, message: Uint8Array) => {
  const a = new Uint8Array(16), a0 = message.length;
  let a1 = 1 << 11, b = key.getUint16(0, true), c = key.getUint16(2, true);
  let d = key.getUint16(4, true), e = key.getUint16(6, true), a2, a3, a4, a5;
  let f = key.getUint16(8, true), g = key.getUint16(10, true), a6, a7, a8;
  let h = key.getUint16(12, true), i = key.getUint16(14, true), j = b & F;
  let k = (b >>> 13 | c << 3) & F, l = (c >> 10 | d << 6) & 0x1f03;
  let m = (d >> 7 | e << 9) & F, n = (e >> 4 | f << 12) & 0xff;
  let o = (f >> 14 | g << 2) & F, p = (g >> 11 | h << 5) & 0x1f81;
  let q = (h >> 8 | i << 8) & F, r = f >> 1 & 0x1ffe, s = i >> 5 & 0x7f;
  let t = f = 0, u = g = 0, v = h = 0, w = i = 0, x = 0, y = 0, z = 0;
  while (a1 && z < a0) {
    a0 - z < 16 &&
      (a.set(message.subarray(z)), a1 = z = a[a0 - z]++, message = a);
    b = message[z++] | message[z++] << 8, c = message[z++] | message[z++] << 8;
    a2 = (b & F) + f, a3 = ((b >>> 13 | c << 3) & F) + g;
    d = message[z++] | message[z++] << 8, e = message[z++] | message[z++] << 8;
    a4 = ((c >> 10 | d << 6) & F) + h, a5 = ((d >> 7 | e << 9) & F) + i;
    b = message[z++] | message[z++] << 8, c = message[z++] | message[z++] << 8;
    a6 = ((e >> 4 | b << 12) & F) + t, a7 = ((b >> 1) & F) + u;
    d = message[z++] | message[z++] << 8, e = message[z++] | message[z++] << 8;
    a8 = ((b >> 14 | c << 2) & F) + v, f = ((c >> 11 | d << 5) & F) + w;
    c = a2 * j + (a3 * s + a4 * q + a5 * p + a6 * o) * 5;
    g = x + ((d >> 8 | e << 8) & F), y += e >> 5 | a1, b = c >>> 13;
    c = (c & F) + (a7 * r + a8 * n + f * m + g * l + k * y) * 5, d = c >>> 13;
    d += b + a2 * k + a3 * j + (a4 * s + a5 * q + a6 * p) * 5, b = d >>> 13;
    d = (d & F) + (a7 * o + a8 * r + f * n + g * m + l * y) * 5, e = d >>> 13;
    e += b + a2 * l + a3 * k + a4 * j + (a5 * s + a6 * q) * 5, b = e >>> 13;
    e = (e & F) + (a7 * p + a8 * o + f * r + g * n + m * y) * 5, h = e & F;
    e = b + (e >>> 13) + a2 * m + a3 * l + a4 * k + a5 * j + a6 * s * 5;
    b = e >>> 13, e = (e & F) + (a7 * q + a8 * p + f * o + g * r + n * y) * 5;
    i = e & F, e = b + (e >>> 13) + a2 * n + a3 * m + a4 * l + a5 * k + a6 * j;
    b = e >>> 13, e = (e & F) + (a7 * s + a8 * q + f * p + g * o + r * y) * 5;
    t = e & F, e = b + (e >>> 13) + a2 * r + a3 * n + a4 * m + a5 * l + a6 * k;
    b = e >>> 13, e = (e & F) + a7 * j + (a8 * s + f * q + g * p + o * y) * 5;
    u = e & F, e = b + (e >>> 13) + a2 * o + a3 * r + a4 * n + a5 * m + a6 * l;
    b = e >>> 13, e = (e & F) + a7 * k + a8 * j + (f * s + g * q + p * y) * 5;
    v = e & F, e = b + (e >>> 13) + a2 * p + a3 * o + a4 * r + a5 * n + a6 * m;
    b = e >>> 13, e = (e & F) + a7 * l + a8 * k + f * j + (g * s + q * y) * 5;
    w = e & F, e = b + (e >>> 13) + a2 * q + a3 * p + a4 * o + a5 * r + a6 * n;
    b = e >>> 13, e = (e & F) + a7 * m + a8 * l + f * k + g * j + y * s * 5;
    x = e & F, e = b + (e >>> 13) + a2 * s + a3 * q + a4 * p + a5 * o + a6 * r;
    y = (e & F) + a7 * n + a8 * m + f * l + g * k + y * j;
    f = ((e >>> 13) + (y >>> 13)) * 5 + (c & F), g = (d & F) + (f >>> 13);
    c = a2 * j + (a3 * s + a4 * q + a5 * p + a6 * o) * 5, f &= F, y &= F;
  }
  h += g >>> 13, i += h >>> 13, t += i >>> 13, u += t >>> 13, v += u >>> 13;
  w += v >>> 13, x += w >>> 13, y += x >>> 13, f += (y >>> 13) * 5, i &= F;
  g = (g & F) + (f >>> 13), h += g >>> 13, f &= F, g &= F, h &= F, t &= F;
  j = f + 5, k = g + (j >>> 13), l = h + (k >>> 13), m = i + (l >>> 13), u &= F;
  n = t + (m >>> 13), r = u + (n >>> 13), v &= F, o = v + (r >>> 13), w &= F;
  x &= F, y &= F, p = w + (o >>> 13), q = x + (p >>> 13), s = y + (q >>> 13);
  b = -(s >>> 13 ^ 1), c = ~b & F, s = (s & F) - (1 << 13), f = f & b | j & c;
  g = g & b | k & c, h = h & b | l & c, i = i & b | m & c, t = t & b | n & c;
  u = u & b | r & c, v = v & b | o & c, w = w & b | p & c, x = x & b | q & c;
  y = y & b | s & c, a[0] = f = ((f | g << 13) & E) + key.getUint16(16, true);
  a[2] = g = (f >> 16) + (g >> 3 | h << 10 & E) + key.getUint16(18, true);
  a[4] = h = (g >> 16) + (h >> 6 | i << 7 & E) + key.getUint16(20, true);
  a[6] = i = (h >> 16) + (i >> 9 | t << 4 & E) + key.getUint16(22, true);
  t = (i >> 16) + ((t >> 12 | u << 1 | v << 14) & E) + key.getUint16(24, true);
  a[10] = u = (t >> 16) + (v >> 2 | w << 11 & E) + key.getUint16(26, true);
  a[12] = v = (u >> 16) + (w >> 5 | x << 8 & E) + key.getUint16(28, true);
  a[14] = w = (v >> 16) + (x >> 8 | y << 5 & E) + key.getUint16(30, true);
  a[1] = f >> 8, a[3] = g >> 8, a[5] = h >> 8, a[7] = i >> 8, a[8] = t;
  return a[9] = t >> 8, a[11] = u >> 8, a[13] = v >> 8, a[15] = w >> 8, a;
};
/** XORs the message with a keystream. */
const xor = (key: DataView, iv: DataView, text: Uint8Array, to: Uint8Array) => {
  const a = iv.getUint32(16, true), b = iv.getUint32(20, true), c = text.length;
  const d = c & ~63, e = new Uint32Array(16);
  let f = new DataView(to.buffer), z = 0, y = 1, x;
  while (z < d) {
    chacha(key, y++, x = 0, a, b, e);
    do f.setUint32(
      z,
      (text[z++] | text[z++] << 8 | text[z++] << 16 | text[z++] << 24) ^ e[x],
      true,
    ); while (++x < 16);
  }
  if (d < c) {
    chacha(key, y, x = 0, a, b, e), f = new DataView(e.buffer);
    do to[z] = text[z] ^ f.getUint8(x++); while (++z < c);
  }
};
/** Calculates a {@linkcode poly | Poly1305} tag. */
const tag = (key: Uint32Array, associated: Uint8Array, text: Uint8Array) => {
  const a = new DataView(key.buffer), b = associated.length, c = text.length;
  const d = b + 15 & ~15, e = c + d + 15 & ~15, f = new Uint8Array(e + 16);
  f.set(associated), f.set(text, d), f[e] = b, f[e + 1] = b >> 8;
  f[e + 2] = b >> 16, f[e + 3] = b >> 24, f[e + 8] = c, f[e + 9] = c >> 8;
  return f[e + 10] = c >> 16, f[e + 11] = c >> 24, poly(a, f);
};
/** Encrypts and appends the authentication tag. */
export const xchacha_poly = (
  key: Uint8Array,
  iv: Uint8Array,
  text: Uint8Array,
  data: Uint8Array,
) => {
  if (key.length !== 32 || iv.length !== 24) return new Uint8Array();
  const a = new Uint32Array(16), b = new DataView(iv.buffer, iv.byteOffset);
  const c = hchacha(a, new DataView(key.buffer, key.byteOffset), b);
  chacha(c, 0, 0, b.getUint32(16, true), b.getUint32(20, true), a);
  const d = text.length, e = new Uint8Array(d + 16);
  return xor(c, b, text, e), e.set(tag(a, data, e.subarray(0, d)), d), e;
};
/** Verifies the authentication tag and decrypts if valid. */
export const poly_xchacha = (
  key: Uint8Array,
  iv: Uint8Array,
  text: Uint8Array,
  data: Uint8Array,
) => {
  if (key.length !== 32 || iv.length !== 24) return false;
  const a = new Uint32Array(16), b = new DataView(iv.buffer, iv.byteOffset);
  const c = hchacha(a, new DataView(key.buffer, key.byteOffset), b);
  const d = text.length - 16, e = new Uint8Array(d);
  chacha(c, 0, 0, b.getUint32(16, true), b.getUint32(20, true), a);
  const f = tag(a, data, text.subarray(0, d));
  let z = 16, y = 0;
  do y |= f[--z] ^ text[d + z]; while (z);
  return !y && (xor(c, b, text.subarray(0, d), e), e);
};
/**
 * Encrypts with XChaCha20Poly1305.
 *
 * @param key Symmetric encryption key.
 * @param text Plaintext to encrypt.
 * @param data Associated data.
 * @returns Concatenation of IV, ciphertext, and tag.
 */
export const encrypt = (
  key: Uint8Array,
  text: Uint8Array,
  data = new Uint8Array(),
) => {
  const a = crypto.getRandomValues(new Uint8Array(24));
  const b = xchacha_poly(key, a, text, data), c = new Uint8Array(b.length + 24);
  return c.set(a), c.set(b, 24), c;
};
/**
 * Decrypts with XChaCha20Poly1305.
 *
 * @param key Symmetric decryption key.
 * @param encrypted Concatenation of IV, ciphertext, and tag.
 * @param data Associated data.
 * @returns Plaintext, or `false` if decryption failed.
 */
export const decrypt = (
  key: Uint8Array,
  encrypted: Uint8Array,
  data = new Uint8Array(),
) => poly_xchacha(key, encrypted.subarray(0, 24), encrypted.subarray(24), data);

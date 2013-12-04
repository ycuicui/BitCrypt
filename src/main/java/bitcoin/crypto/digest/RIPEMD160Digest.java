/**
 * Copyright (c) 2000 - 2013 The Legion of the Bouncy Castle Inc.
 * (http://www.bouncycastle.org)
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to permit
 * persons to whom the Software is furnished to do so, subject to the
 * following conditions:
 * 
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
 * NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 */
package bitcoin.crypto.digest;

import jsr305.NonNull;

/**
 * implementation of RIPEMD see,
 * http://www.esat.kuleuven.ac.be/~bosselae/ripemd160.html
 */
public class RIPEMD160Digest {

	public static final int DIGEST_LENGTH = 20;

	private final byte[] xBuf = new byte[4];

	private int xBufOff = 0;

	private long byteCount;

	// IV's
	private int H0 = 0x67452301;
	private int H1 = 0xefcdab89;
	private int H2 = 0x98badcfe;
	private int H3 = 0x10325476;
	private int H4 = 0xc3d2e1f0;

	private final int[] X = new int[16];

	private int xOff;

	/**
	 * Standard constructor
	 */
	public RIPEMD160Digest() {
		reset();
	}

	/**
	 * This method replace the following code
	 * 
	 * <pre>
	 * dgst.update(in);
	 * final byte[] out = new byte[20];
	 * dgst.doFinal(out, 0);
	 * return out;
	 * </pre>
	 * 
	 * @param in
	 * @return
	 */
	public byte[] getDigest(@NonNull final byte[] in) {
		update(in);
		return doFinal();
	}

	private void update(@NonNull final byte[] in) {

		int inOff = 0;
		int len = in.length;

		// fill the current word
		while (xBufOff != 0 && len > 0) {
			update(in[inOff]);

			inOff++;
			len--;
		}

		// process whole words.
		while (len > xBuf.length) {
			processWord(in, inOff);

			inOff += xBuf.length;
			len -= xBuf.length;
			byteCount += xBuf.length;
		}

		// load in the remainder.
		while (len > 0) {
			update(in[inOff]);

			inOff++;
			len--;
		}
	}

	private byte[] doFinal() {
		finish();

		final byte[] out = new byte[DIGEST_LENGTH];

		unpackWord(H0, out, 0);
		unpackWord(H1, out, 4);
		unpackWord(H2, out, 8);
		unpackWord(H3, out, 12);
		unpackWord(H4, out, 16);

		reset();

		return out;
	}

	private void finish() {
		final long bitLength = byteCount << 3;

		// add the pad bytes.
		update((byte) 128);

		while (xBufOff != 0) {
			update((byte) 0);
		}

		processLength(bitLength);
		processBlock();
	}

	private void update(final byte in) {
		xBuf[xBufOff++] = in;

		if (xBufOff == xBuf.length) {
			processWord(xBuf, 0);
			xBufOff = 0;
		}

		byteCount++;
	}

	private void processWord(@NonNull final byte[] in, final int inOff) {
		X[xOff++] = in[inOff] & 0xff | (in[inOff + 1] & 0xff) << 8
				| (in[inOff + 2] & 0xff) << 16 | (in[inOff + 3] & 0xff) << 24;

		if (xOff == 16) {
			processBlock();
		}
	}

	private void processLength(final long bitLength) {
		if (xOff > 14) {
			processBlock();
		}

		X[14] = (int) (bitLength & 0xffffffff);
		X[15] = (int) (bitLength >>> 32);
	}

	private static void unpackWord(final int word, @NonNull final byte[] out,
			final int outOff) {
		out[outOff] = (byte) word;
		out[outOff + 1] = (byte) (word >>> 8);
		out[outOff + 2] = (byte) (word >>> 16);
		out[outOff + 3] = (byte) (word >>> 24);
	}

	/**
	 * reset the chaining variables to the IV values.
	 */
	private void reset() {
		byteCount = 0;

		xBufOff = 0;
		for (int i = 0; i < xBuf.length; i++) {
			xBuf[i] = 0;
		}

		H0 = 0x67452301;
		H1 = 0xefcdab89;
		H2 = 0x98badcfe;
		H3 = 0x10325476;
		H4 = 0xc3d2e1f0;

		xOff = 0;

		for (int i = 0; i != X.length; i++) {
			X[i] = 0;
		}
	}

	/*
	 * rotate int x left n bits.
	 */
	private static int RL(final int x, final int n) {
		return x << n | x >>> 32 - n;
	}

	// ////////////////////////////////////////////////////////////////////////
	// f1,f2,f3,f4,f5 are the basic RIPEMD160 functions.
	// //////////////////////////////////////////////////////////////////////

	/*
	 * rounds 0-15
	 */
	private static int f1(final int x, final int y, final int z) {
		return x ^ y ^ z;
	}

	/*
	 * rounds 16-31
	 */
	private static int f2(final int x, final int y, final int z) {
		return x & y | ~x & z;
	}

	/*
	 * rounds 32-47
	 */
	private static int f3(final int x, final int y, final int z) {
		return (x | ~y) ^ z;
	}

	/*
	 * rounds 48-63
	 */
	private static int f4(final int x, final int y, final int z) {
		return x & z | y & ~z;
	}

	/*
	 * rounds 64-79
	 */
	private static int f5(final int x, final int y, final int z) {
		return x ^ (y | ~z);
	}

	private void processBlock() {
		int a, aa;
		int b, bb;
		int c, cc;
		int d, dd;
		int e, ee;

		a = aa = H0;
		b = bb = H1;
		c = cc = H2;
		d = dd = H3;
		e = ee = H4;

		//
		// Rounds 1 - 16
		//
		// left
		a = RL(a + f1(b, c, d) + X[0], 11) + e;
		c = RL(c, 10);
		e = RL(e + f1(a, b, c) + X[1], 14) + d;
		b = RL(b, 10);
		d = RL(d + f1(e, a, b) + X[2], 15) + c;
		a = RL(a, 10);
		c = RL(c + f1(d, e, a) + X[3], 12) + b;
		e = RL(e, 10);
		b = RL(b + f1(c, d, e) + X[4], 5) + a;
		d = RL(d, 10);
		a = RL(a + f1(b, c, d) + X[5], 8) + e;
		c = RL(c, 10);
		e = RL(e + f1(a, b, c) + X[6], 7) + d;
		b = RL(b, 10);
		d = RL(d + f1(e, a, b) + X[7], 9) + c;
		a = RL(a, 10);
		c = RL(c + f1(d, e, a) + X[8], 11) + b;
		e = RL(e, 10);
		b = RL(b + f1(c, d, e) + X[9], 13) + a;
		d = RL(d, 10);
		a = RL(a + f1(b, c, d) + X[10], 14) + e;
		c = RL(c, 10);
		e = RL(e + f1(a, b, c) + X[11], 15) + d;
		b = RL(b, 10);
		d = RL(d + f1(e, a, b) + X[12], 6) + c;
		a = RL(a, 10);
		c = RL(c + f1(d, e, a) + X[13], 7) + b;
		e = RL(e, 10);
		b = RL(b + f1(c, d, e) + X[14], 9) + a;
		d = RL(d, 10);
		a = RL(a + f1(b, c, d) + X[15], 8) + e;
		c = RL(c, 10);

		// right
		aa = RL(aa + f5(bb, cc, dd) + X[5] + 0x50a28be6, 8) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f5(aa, bb, cc) + X[14] + 0x50a28be6, 9) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f5(ee, aa, bb) + X[7] + 0x50a28be6, 9) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f5(dd, ee, aa) + X[0] + 0x50a28be6, 11) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f5(cc, dd, ee) + X[9] + 0x50a28be6, 13) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f5(bb, cc, dd) + X[2] + 0x50a28be6, 15) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f5(aa, bb, cc) + X[11] + 0x50a28be6, 15) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f5(ee, aa, bb) + X[4] + 0x50a28be6, 5) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f5(dd, ee, aa) + X[13] + 0x50a28be6, 7) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f5(cc, dd, ee) + X[6] + 0x50a28be6, 7) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f5(bb, cc, dd) + X[15] + 0x50a28be6, 8) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f5(aa, bb, cc) + X[8] + 0x50a28be6, 11) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f5(ee, aa, bb) + X[1] + 0x50a28be6, 14) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f5(dd, ee, aa) + X[10] + 0x50a28be6, 14) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f5(cc, dd, ee) + X[3] + 0x50a28be6, 12) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f5(bb, cc, dd) + X[12] + 0x50a28be6, 6) + ee;
		cc = RL(cc, 10);

		//
		// Rounds 16-31
		//
		// left
		e = RL(e + f2(a, b, c) + X[7] + 0x5a827999, 7) + d;
		b = RL(b, 10);
		d = RL(d + f2(e, a, b) + X[4] + 0x5a827999, 6) + c;
		a = RL(a, 10);
		c = RL(c + f2(d, e, a) + X[13] + 0x5a827999, 8) + b;
		e = RL(e, 10);
		b = RL(b + f2(c, d, e) + X[1] + 0x5a827999, 13) + a;
		d = RL(d, 10);
		a = RL(a + f2(b, c, d) + X[10] + 0x5a827999, 11) + e;
		c = RL(c, 10);
		e = RL(e + f2(a, b, c) + X[6] + 0x5a827999, 9) + d;
		b = RL(b, 10);
		d = RL(d + f2(e, a, b) + X[15] + 0x5a827999, 7) + c;
		a = RL(a, 10);
		c = RL(c + f2(d, e, a) + X[3] + 0x5a827999, 15) + b;
		e = RL(e, 10);
		b = RL(b + f2(c, d, e) + X[12] + 0x5a827999, 7) + a;
		d = RL(d, 10);
		a = RL(a + f2(b, c, d) + X[0] + 0x5a827999, 12) + e;
		c = RL(c, 10);
		e = RL(e + f2(a, b, c) + X[9] + 0x5a827999, 15) + d;
		b = RL(b, 10);
		d = RL(d + f2(e, a, b) + X[5] + 0x5a827999, 9) + c;
		a = RL(a, 10);
		c = RL(c + f2(d, e, a) + X[2] + 0x5a827999, 11) + b;
		e = RL(e, 10);
		b = RL(b + f2(c, d, e) + X[14] + 0x5a827999, 7) + a;
		d = RL(d, 10);
		a = RL(a + f2(b, c, d) + X[11] + 0x5a827999, 13) + e;
		c = RL(c, 10);
		e = RL(e + f2(a, b, c) + X[8] + 0x5a827999, 12) + d;
		b = RL(b, 10);

		// right
		ee = RL(ee + f4(aa, bb, cc) + X[6] + 0x5c4dd124, 9) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f4(ee, aa, bb) + X[11] + 0x5c4dd124, 13) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f4(dd, ee, aa) + X[3] + 0x5c4dd124, 15) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f4(cc, dd, ee) + X[7] + 0x5c4dd124, 7) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f4(bb, cc, dd) + X[0] + 0x5c4dd124, 12) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f4(aa, bb, cc) + X[13] + 0x5c4dd124, 8) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f4(ee, aa, bb) + X[5] + 0x5c4dd124, 9) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f4(dd, ee, aa) + X[10] + 0x5c4dd124, 11) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f4(cc, dd, ee) + X[14] + 0x5c4dd124, 7) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f4(bb, cc, dd) + X[15] + 0x5c4dd124, 7) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f4(aa, bb, cc) + X[8] + 0x5c4dd124, 12) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f4(ee, aa, bb) + X[12] + 0x5c4dd124, 7) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f4(dd, ee, aa) + X[4] + 0x5c4dd124, 6) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f4(cc, dd, ee) + X[9] + 0x5c4dd124, 15) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f4(bb, cc, dd) + X[1] + 0x5c4dd124, 13) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f4(aa, bb, cc) + X[2] + 0x5c4dd124, 11) + dd;
		bb = RL(bb, 10);

		//
		// Rounds 32-47
		//
		// left
		d = RL(d + f3(e, a, b) + X[3] + 0x6ed9eba1, 11) + c;
		a = RL(a, 10);
		c = RL(c + f3(d, e, a) + X[10] + 0x6ed9eba1, 13) + b;
		e = RL(e, 10);
		b = RL(b + f3(c, d, e) + X[14] + 0x6ed9eba1, 6) + a;
		d = RL(d, 10);
		a = RL(a + f3(b, c, d) + X[4] + 0x6ed9eba1, 7) + e;
		c = RL(c, 10);
		e = RL(e + f3(a, b, c) + X[9] + 0x6ed9eba1, 14) + d;
		b = RL(b, 10);
		d = RL(d + f3(e, a, b) + X[15] + 0x6ed9eba1, 9) + c;
		a = RL(a, 10);
		c = RL(c + f3(d, e, a) + X[8] + 0x6ed9eba1, 13) + b;
		e = RL(e, 10);
		b = RL(b + f3(c, d, e) + X[1] + 0x6ed9eba1, 15) + a;
		d = RL(d, 10);
		a = RL(a + f3(b, c, d) + X[2] + 0x6ed9eba1, 14) + e;
		c = RL(c, 10);
		e = RL(e + f3(a, b, c) + X[7] + 0x6ed9eba1, 8) + d;
		b = RL(b, 10);
		d = RL(d + f3(e, a, b) + X[0] + 0x6ed9eba1, 13) + c;
		a = RL(a, 10);
		c = RL(c + f3(d, e, a) + X[6] + 0x6ed9eba1, 6) + b;
		e = RL(e, 10);
		b = RL(b + f3(c, d, e) + X[13] + 0x6ed9eba1, 5) + a;
		d = RL(d, 10);
		a = RL(a + f3(b, c, d) + X[11] + 0x6ed9eba1, 12) + e;
		c = RL(c, 10);
		e = RL(e + f3(a, b, c) + X[5] + 0x6ed9eba1, 7) + d;
		b = RL(b, 10);
		d = RL(d + f3(e, a, b) + X[12] + 0x6ed9eba1, 5) + c;
		a = RL(a, 10);

		// right
		dd = RL(dd + f3(ee, aa, bb) + X[15] + 0x6d703ef3, 9) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f3(dd, ee, aa) + X[5] + 0x6d703ef3, 7) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f3(cc, dd, ee) + X[1] + 0x6d703ef3, 15) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f3(bb, cc, dd) + X[3] + 0x6d703ef3, 11) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f3(aa, bb, cc) + X[7] + 0x6d703ef3, 8) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f3(ee, aa, bb) + X[14] + 0x6d703ef3, 6) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f3(dd, ee, aa) + X[6] + 0x6d703ef3, 6) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f3(cc, dd, ee) + X[9] + 0x6d703ef3, 14) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f3(bb, cc, dd) + X[11] + 0x6d703ef3, 12) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f3(aa, bb, cc) + X[8] + 0x6d703ef3, 13) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f3(ee, aa, bb) + X[12] + 0x6d703ef3, 5) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f3(dd, ee, aa) + X[2] + 0x6d703ef3, 14) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f3(cc, dd, ee) + X[10] + 0x6d703ef3, 13) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f3(bb, cc, dd) + X[0] + 0x6d703ef3, 13) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f3(aa, bb, cc) + X[4] + 0x6d703ef3, 7) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f3(ee, aa, bb) + X[13] + 0x6d703ef3, 5) + cc;
		aa = RL(aa, 10);

		//
		// Rounds 48-63
		//
		// left
		c = RL(c + f4(d, e, a) + X[1] + 0x8f1bbcdc, 11) + b;
		e = RL(e, 10);
		b = RL(b + f4(c, d, e) + X[9] + 0x8f1bbcdc, 12) + a;
		d = RL(d, 10);
		a = RL(a + f4(b, c, d) + X[11] + 0x8f1bbcdc, 14) + e;
		c = RL(c, 10);
		e = RL(e + f4(a, b, c) + X[10] + 0x8f1bbcdc, 15) + d;
		b = RL(b, 10);
		d = RL(d + f4(e, a, b) + X[0] + 0x8f1bbcdc, 14) + c;
		a = RL(a, 10);
		c = RL(c + f4(d, e, a) + X[8] + 0x8f1bbcdc, 15) + b;
		e = RL(e, 10);
		b = RL(b + f4(c, d, e) + X[12] + 0x8f1bbcdc, 9) + a;
		d = RL(d, 10);
		a = RL(a + f4(b, c, d) + X[4] + 0x8f1bbcdc, 8) + e;
		c = RL(c, 10);
		e = RL(e + f4(a, b, c) + X[13] + 0x8f1bbcdc, 9) + d;
		b = RL(b, 10);
		d = RL(d + f4(e, a, b) + X[3] + 0x8f1bbcdc, 14) + c;
		a = RL(a, 10);
		c = RL(c + f4(d, e, a) + X[7] + 0x8f1bbcdc, 5) + b;
		e = RL(e, 10);
		b = RL(b + f4(c, d, e) + X[15] + 0x8f1bbcdc, 6) + a;
		d = RL(d, 10);
		a = RL(a + f4(b, c, d) + X[14] + 0x8f1bbcdc, 8) + e;
		c = RL(c, 10);
		e = RL(e + f4(a, b, c) + X[5] + 0x8f1bbcdc, 6) + d;
		b = RL(b, 10);
		d = RL(d + f4(e, a, b) + X[6] + 0x8f1bbcdc, 5) + c;
		a = RL(a, 10);
		c = RL(c + f4(d, e, a) + X[2] + 0x8f1bbcdc, 12) + b;
		e = RL(e, 10);

		// right
		cc = RL(cc + f2(dd, ee, aa) + X[8] + 0x7a6d76e9, 15) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f2(cc, dd, ee) + X[6] + 0x7a6d76e9, 5) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f2(bb, cc, dd) + X[4] + 0x7a6d76e9, 8) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f2(aa, bb, cc) + X[1] + 0x7a6d76e9, 11) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f2(ee, aa, bb) + X[3] + 0x7a6d76e9, 14) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f2(dd, ee, aa) + X[11] + 0x7a6d76e9, 14) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f2(cc, dd, ee) + X[15] + 0x7a6d76e9, 6) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f2(bb, cc, dd) + X[0] + 0x7a6d76e9, 14) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f2(aa, bb, cc) + X[5] + 0x7a6d76e9, 6) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f2(ee, aa, bb) + X[12] + 0x7a6d76e9, 9) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f2(dd, ee, aa) + X[2] + 0x7a6d76e9, 12) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f2(cc, dd, ee) + X[13] + 0x7a6d76e9, 9) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f2(bb, cc, dd) + X[9] + 0x7a6d76e9, 12) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f2(aa, bb, cc) + X[7] + 0x7a6d76e9, 5) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f2(ee, aa, bb) + X[10] + 0x7a6d76e9, 15) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f2(dd, ee, aa) + X[14] + 0x7a6d76e9, 8) + bb;
		ee = RL(ee, 10);

		//
		// Rounds 64-79
		//
		// left
		b = RL(b + f5(c, d, e) + X[4] + 0xa953fd4e, 9) + a;
		d = RL(d, 10);
		a = RL(a + f5(b, c, d) + X[0] + 0xa953fd4e, 15) + e;
		c = RL(c, 10);
		e = RL(e + f5(a, b, c) + X[5] + 0xa953fd4e, 5) + d;
		b = RL(b, 10);
		d = RL(d + f5(e, a, b) + X[9] + 0xa953fd4e, 11) + c;
		a = RL(a, 10);
		c = RL(c + f5(d, e, a) + X[7] + 0xa953fd4e, 6) + b;
		e = RL(e, 10);
		b = RL(b + f5(c, d, e) + X[12] + 0xa953fd4e, 8) + a;
		d = RL(d, 10);
		a = RL(a + f5(b, c, d) + X[2] + 0xa953fd4e, 13) + e;
		c = RL(c, 10);
		e = RL(e + f5(a, b, c) + X[10] + 0xa953fd4e, 12) + d;
		b = RL(b, 10);
		d = RL(d + f5(e, a, b) + X[14] + 0xa953fd4e, 5) + c;
		a = RL(a, 10);
		c = RL(c + f5(d, e, a) + X[1] + 0xa953fd4e, 12) + b;
		e = RL(e, 10);
		b = RL(b + f5(c, d, e) + X[3] + 0xa953fd4e, 13) + a;
		d = RL(d, 10);
		a = RL(a + f5(b, c, d) + X[8] + 0xa953fd4e, 14) + e;
		c = RL(c, 10);
		e = RL(e + f5(a, b, c) + X[11] + 0xa953fd4e, 11) + d;
		b = RL(b, 10);
		d = RL(d + f5(e, a, b) + X[6] + 0xa953fd4e, 8) + c;
		a = RL(a, 10);
		c = RL(c + f5(d, e, a) + X[15] + 0xa953fd4e, 5) + b;
		e = RL(e, 10);
		b = RL(b + f5(c, d, e) + X[13] + 0xa953fd4e, 6) + a;
		d = RL(d, 10);

		// right
		bb = RL(bb + f1(cc, dd, ee) + X[12], 8) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f1(bb, cc, dd) + X[15], 5) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f1(aa, bb, cc) + X[10], 12) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f1(ee, aa, bb) + X[4], 9) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f1(dd, ee, aa) + X[1], 12) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f1(cc, dd, ee) + X[5], 5) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f1(bb, cc, dd) + X[8], 14) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f1(aa, bb, cc) + X[7], 6) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f1(ee, aa, bb) + X[6], 8) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f1(dd, ee, aa) + X[2], 13) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f1(cc, dd, ee) + X[13], 6) + aa;
		dd = RL(dd, 10);
		aa = RL(aa + f1(bb, cc, dd) + X[14], 5) + ee;
		cc = RL(cc, 10);
		ee = RL(ee + f1(aa, bb, cc) + X[0], 15) + dd;
		bb = RL(bb, 10);
		dd = RL(dd + f1(ee, aa, bb) + X[3], 13) + cc;
		aa = RL(aa, 10);
		cc = RL(cc + f1(dd, ee, aa) + X[9], 11) + bb;
		ee = RL(ee, 10);
		bb = RL(bb + f1(cc, dd, ee) + X[11], 11) + aa;
		dd = RL(dd, 10);

		dd += c + H1;
		H1 = H2 + d + ee;
		H2 = H3 + e + aa;
		H3 = H4 + a + bb;
		H4 = H0 + b + cc;
		H0 = dd;

		//
		// reset the offset and clean out the word buffer.
		//
		xOff = 0;
		for (int i = 0; i != X.length; i++) {
			X[i] = 0;
		}
	}
}

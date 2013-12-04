/**
 * This work is released under the BSD Licence
 * 
 * Copyright (c) 2013, Yves Cuillerdier 
 * All rights reserved.
 * 
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *   o Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer. 
 *   o Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution. 
 *   o Neither the name Yves Cuillerdier nor the names of its contributors may 
 *     be used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package bitcoin.crypto.curve;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import org.junit.Assert;
import org.junit.Ignore;
import org.junit.Test;

/**
 * @author Yves Cuillerdier <yves@cuillerdier.net>
 */
@SuppressWarnings("unused")
public class ECPointTest implements ECCurve {

	private final Random RAND = new Random();

	private static final Random SECURE_RANDOM = new SecureRandom();

	@Test
	public void testECPointBigIntegerBooleanYValue() {
		final boolean even = RAND.nextBoolean();
		while (true) {
			// Generate x
			final BigInteger x = new BigInteger(256, SECURE_RANDOM).mod(N);
			try {
				final ECPoint p = new ECPoint(x, even);

				final ECFieldElement y = p.getY();
				if (y == null) {
					Assert.fail();
					return;
				}
				Assert.assertTrue(y.value.testBit(0) != even);
				return;
			} catch (final IllegalArgumentException iae) {
				// try again
			}
		}
	}

	/**
	 * Pour x donné, on a 1 chance /2 qu'il existe un point sur la courbe
	 */

	@Test
	public void testECPointBigIntegerBooleanProba() {
		final int TEST_COUNT = 2000;
		int success = 0;
		for (int i = 0; i < TEST_COUNT; i++) {
			// Generate x
			final BigInteger x = new BigInteger(256, SECURE_RANDOM).mod(N);
			try {
				new ECPoint(x, RAND.nextBoolean());
				success++;
			} catch (final IllegalArgumentException iae) {
				// try again
			}
		}
		final double gain = success / (double) TEST_COUNT;
		System.out.println("Success: " + gain); //$NON-NLS-1$
		Assert.assertTrue(gain > 0.45 && gain < 0.55);
	}

	@Test
	public void testEncodeInfinity() {
		// Good encoding
		byte[] bytes = O.getEncoded(RAND.nextBoolean());
		final ECPoint pt = new ECPoint(bytes);
		Assert.assertTrue(pt.isInfinity());

		// Bad encoding
		bytes = new byte[2];
		try {
			new ECPoint(bytes);
			Assert.fail();
		} catch (final RuntimeException e) {
			// Success
		}
	}

	@Test
	public void testEncodeUncompressed() {
		// Generate point
		final boolean even = RAND.nextBoolean();
		final ECPoint pt1 = generateValidPoint();

		final ECPoint pt2 = new ECPoint(pt1.getEncoded(false));

		Assert.assertEquals(pt1, pt2);

		// Fail
		final byte[] bytes = new byte[66];
		System.arraycopy(pt1.getEncoded(false), 0, bytes, 0, 65);
		try {
			new ECPoint(bytes);
			Assert.fail();
		} catch (final RuntimeException e) {
			// Success
		}
	}

	@Test
	public void testEncodeCompressedEven() {
		// Generate point
		final ECPoint pt1 = generateValidPoint();

		final ECPoint pt2 = new ECPoint(pt1.getEncoded(true));

		Assert.assertEquals(pt1, pt2);

		// Fail
		final byte[] bytes = new byte[34];
		System.arraycopy(pt1.getEncoded(true), 0, bytes, 0, 33);
		try {
			new ECPoint(bytes);
			Assert.fail();
		} catch (final RuntimeException e) {
			// Success
		}
	}

	@Test
	public void testEncodeCompressedOdd() {
		// Generate point
		final ECPoint pt1 = generateValidPoint();

		final ECPoint pt2 = new ECPoint(pt1.getEncoded(true));

		Assert.assertEquals(pt1, pt2);

		// Fail
		final byte[] bytes = new byte[34];
		System.arraycopy(pt1.getEncoded(true), 0, bytes, 0, 33);
		try {
			new ECPoint(bytes);
			Assert.fail();
		} catch (final RuntimeException e) {
			// Success
		}
	}

	@SuppressWarnings("static-method")
	@Test
	public void testBadEncode() {
		final byte[] bytes = new byte[10];
		bytes[0] = 0x10;
		try {
			new ECPoint(bytes);
			Assert.fail();
		} catch (final RuntimeException e) {
			// OK
		}
	}

	@Test
	public void testAddInfinity() {
		// Generate valid point
		final ECPoint p = generateValidPoint();

		// Add infinity
		Assert.assertEquals(p, p.add(O));
		Assert.assertEquals(p, O.add(p));

		Assert.assertEquals(O, O.add(O));
	}

	@Test
	public void testAddSameIsTwice() {
		// Generate valid point
		final ECPoint p = generateValidPoint();

		// Add
		Assert.assertEquals(p.twice(), p.add(p));

		// Add Infinity+Infinity
		Assert.assertEquals(O.twice(), O);
	}

	@Test
	public void testAddOposite() {
		// Generate valid point
		final ECPoint p = generateValidPoint();

		// Add
		Assert.assertEquals(O, p.add(p.negate()));

		// Negate infinity
		Assert.assertEquals(O, O.add(O.negate()));
	}

	@SuppressWarnings("static-method")
	@Test
	public void testNegateInfinity() {
		Assert.assertEquals(O, O.negate());
	}

	@Test
	public void testMultiply0() {
		// Generate valid point
		final ECPoint p = generateValidPoint();

		// * 0
		Assert.assertEquals(O, p.multiply(BigInteger.ZERO));

		Assert.assertEquals(O, O.multiply(BigInteger.ZERO));
	}

	@Test
	public void testMultiply1() {
		// Generate valid point
		final ECPoint p = generateValidPoint();

		// * 1
		Assert.assertEquals(p, p.multiply(BigInteger.ONE));

		Assert.assertEquals(O, O.multiply(BigInteger.ONE));
	}

	@Test
	public void testMultiply() {
		// Generate valid point
		final ECPoint p = generateValidPoint();

		// Multiplicator must be >=0
		try {
			p.multiply(new BigInteger("-1")); //$NON-NLS-1$
			Assert.fail("should throws IllegalArgumentException"); //$NON-NLS-1$
		} catch (final IllegalArgumentException e) {
			// OK
		}

		final BigInteger k1 = new BigInteger(ECCurve.FIELD_SIZE, RAND);
		final BigInteger k2 = new BigInteger(ECCurve.FIELD_SIZE, RAND);

		Assert.assertEquals(p.multiply(k1).multiply(k2), p.multiply(k2)
				.multiply(k1));
	}

	@Test
	public void testIsInfinity() {
		// Generate valid point
		ECPoint p = generateValidPoint();

		p = p.multiply(N);

		Assert.assertTrue(p.isInfinity());
	}

	@Ignore
	@Test
	public void testTwice0IsInfinity() {
		// For thr Bitcoin Curve, there is no points with y=0
	}

	@Test
	public void testEqualThis() {
		final ECPoint p = generateValidPoint();

		Assert.assertTrue(p.equals(p));
	}

	@Test
	public void testEqualsOtherObject() {
		final ECPoint p = generateValidPoint();

		Assert.assertFalse(p.equals(p.getX()));
	}

	@Test
	public void testEqualsNull() {
		final ECPoint p = generateValidPoint();

		Assert.assertFalse(p.equals(null));
	}

	@Test
	public void testEqualsInfinity() {
		final ECPoint p = new ECPoint();

		Assert.assertTrue(p.isInfinity());
		Assert.assertTrue(O.equals(p));
		Assert.assertTrue(p.equals(O));
		Assert.assertFalse(generateValidPoint().equals(O));

	}

	private ECPoint generateValidPoint() {
		while (true) {
			// Generate x
			final BigInteger x = new BigInteger(256, SECURE_RANDOM).mod(N);
			try {
				return new ECPoint(x, RAND.nextBoolean());
			} catch (final IllegalArgumentException iae) {
				// try again
			}
		}
	}
}

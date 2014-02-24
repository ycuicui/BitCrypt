/**
 * Copyright 2013 Yves Cuillerdier.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package bitcoin.crypto.curve;

import java.math.BigInteger;

import junit.framework.Assert;

import org.junit.Test;

import bitcoin.crypto.curve.ECCurve;
import bitcoin.crypto.curve.ECFieldElement;

/**
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
@SuppressWarnings("static-method")
public class ECFieldElementTest implements ECCurve {

	@Test
	public void testSqrBase() {
		// We have P = 4*u + 3
		final BigInteger base = P.shiftRight(2).add(BigInteger.ONE);
		Assert.assertEquals(ECFieldElement.SQR_BASE, base);
	}

	@SuppressWarnings("unused")
	@Test
	public void testECFieldElementBigIntegerError() {
		try {
			new ECFieldElement(P);
		} catch (final IllegalArgumentException e) {
			// Success
		}
	}

	@Test
	public void testInvert() {
		final ECFieldElement elem = new ECFieldElement(new BigInteger(
				FIELD_SIZE, SECURE_RANDOM).mod(P));
		final ECFieldElement inv = elem.invert();

		Assert.assertEquals(new ECFieldElement(BigInteger.ONE),
				elem.multiply(inv));
	}

	@Test
	public void testSqrt() {
		final ECFieldElement elem = new ECFieldElement(new BigInteger(
				FIELD_SIZE, SECURE_RANDOM).mod(P));
		final ECFieldElement elem2 = elem.square();
		final ECFieldElement sqrt = elem2.sqrt();
		Assert.assertTrue(elem.equals(sqrt) || elem.negate().equals(sqrt));
	}

	@Test
	public void testSqrtResidu() {
		final ECFieldElement elem = new ECFieldElement(new BigInteger(
				FIELD_SIZE, SECURE_RANDOM).mod(P));
		final ECFieldElement sqrt = elem.sqrt();

		if (elem.value.modPow(P.subtract(BigInteger.ONE).shiftRight(1), P)
				.equals(BigInteger.ONE)) {
			if (sqrt == null) {
				Assert.fail();
				return;
			}
			Assert.assertEquals(elem, sqrt.square());
		} else {
			Assert.assertNull(sqrt);
		}
	}

	@Test
	public void testEqualThis() {
		final ECFieldElement elem = new ECFieldElement(new BigInteger(
				FIELD_SIZE, SECURE_RANDOM).mod(P));

		Assert.assertTrue(elem.equals(elem));
	}

	@Test
	public void testOtherObject() {
		final ECFieldElement elem = new ECFieldElement(new BigInteger(
				FIELD_SIZE, SECURE_RANDOM).mod(P));

		Assert.assertFalse(elem.equals(elem.value));
	}

	/**
	 * sqrt(-3) exist, then x^2 + x + 1 could be factorized
	 * <p>
	 * x^2 + x + 1=(x-x1)(x-x2)=x^2 + (-x1-x2)x + x1*x2
	 * <p>
	 * Consequently, as P=9u+7, the cube root does not exists for all elements.
	 * For example, x1 and x2 don't have cube root!
	 */
	@Test
	public void testSqrtM3() {
		final ECFieldElement m3 = new ECFieldElement(P.subtract(BigInteger
				.valueOf(3L)));
		final ECFieldElement d = m3.sqrt();

		if (d == null) {
			Assert.fail();
			return;
		}

		final ECFieldElement inv2 = new ECFieldElement(BigInteger.valueOf(2L))
				.invert();
		final ECFieldElement m1 = new ECFieldElement(P.subtract(BigInteger.ONE));

		final ECFieldElement x1 = m1.add(d).multiply(inv2);
		final ECFieldElement x2 = m1.subtract(d).multiply(inv2);

		// X1*X2=1
		Assert.assertEquals(ECFieldElement.ONE, x1.multiply(x2));
		// X1+X2=-1
		Assert.assertEquals(ECFieldElement.ONE, x1.add(x2).negate());
		// X1^3=1
		Assert.assertEquals(ECFieldElement.ONE, x1.square().multiply(x1));
		// X2^3=1
		Assert.assertEquals(ECFieldElement.ONE, x2.square().multiply(x2));
		// X1^2=X2
		Assert.assertEquals(x2, x1.square());
		// X2^2=X1
		Assert.assertEquals(x1, x2.square());
	}
}

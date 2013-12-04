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
import java.util.Random;

import junit.framework.Assert;

import org.junit.Test;

/**
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
@SuppressWarnings("static-method")
public class ECFieldElementTest implements ECCurve {

	private static final Random RAND = new Random();

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
				FIELD_SIZE, RAND).mod(P));
		final ECFieldElement inv = elem.invert();

		Assert.assertEquals(new ECFieldElement(BigInteger.ONE),
				elem.multiply(inv));
	}

	@Test
	public void testSqrt() {
		final ECFieldElement elem = new ECFieldElement(new BigInteger(
				FIELD_SIZE, RAND).mod(P));
		final ECFieldElement elem2 = elem.square();

		final ECFieldElement sqrt = elem2.sqrt();

		Assert.assertTrue(elem.equals(sqrt) || elem.negate().equals(sqrt));
	}

	@Test
	public void testEqualThis() {
		final ECFieldElement elem = new ECFieldElement(new BigInteger(
				FIELD_SIZE, RAND).mod(P));

		Assert.assertTrue(elem.equals(elem));
	}

	@Test
	public void testOtherObject() {
		final ECFieldElement elem = new ECFieldElement(new BigInteger(
				FIELD_SIZE, RAND).mod(P));

		Assert.assertFalse(elem.equals(elem.value));
	}
}

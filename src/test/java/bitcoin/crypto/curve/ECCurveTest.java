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

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
@SuppressWarnings("static-method")
public class ECCurveTest implements ECCurve {

	/** P en decimal */
	private static final BigInteger P_DECI = new BigInteger(
			"115792089237316195423570985008687907853269984665640564039457584007908834671663"); //$NON-NLS-1$

	@Test
	public void testPDecimal() {
		Assert.assertEquals(P, P_DECI);
	}

	@Test
	public void testPIsPrime() {
		Assert.assertTrue(P.isProbablePrime(128));
	}

	@Test
	public void testNIsPrime() {
		Assert.assertTrue(N.isProbablePrime(128));
	}

	@Test
	public final void testNLowerThanP() {
		Assert.assertTrue(N.compareTo(P) < 0);
	}

	@Test
	public final void test2NGreaterThanP() {
		Assert.assertTrue(N.add(N).compareTo(P) > 0);
	}

	@Test
	public final void testNGIsInfinity() {
		final ECPoint ng = G.multiply(N);
		Assert.assertEquals(O, ng);
	}

	@Test
	public void testPm1Mod3() {
		final BigInteger three = BigInteger.valueOf(3);
		final BigInteger pm1 = P.subtract(BigInteger.ONE);
		final BigInteger p3 = pm1.divide(three);

		Assert.assertEquals(pm1, p3.multiply(three));
	}

	@Test
	public void testPm3Mod4() {
		final BigInteger four = BigInteger.valueOf(4);
		final BigInteger pm3 = P.subtract(BigInteger.valueOf(3L));
		final BigInteger p4 = pm3.divide(four);

		Assert.assertEquals(pm3, p4.multiply(four));
	}

	@Test
	public void testPm1Mod6() {
		final BigInteger six = BigInteger.valueOf(6);
		final BigInteger pm1 = P.subtract(BigInteger.valueOf(1L));
		final BigInteger p6 = pm1.divide(six);

		Assert.assertEquals(pm1, p6.multiply(six));
	}

	@Test
	public void testPm7Mod9() {
		final BigInteger nine = BigInteger.valueOf(9);
		final BigInteger pm7 = P.subtract(BigInteger.valueOf(7L));
		final BigInteger p9 = pm7.divide(nine);

		Assert.assertEquals(pm7, p9.multiply(nine));
	}
}

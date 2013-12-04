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

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Yves Cuillerdier <yves@cuillerdier.net>
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
}

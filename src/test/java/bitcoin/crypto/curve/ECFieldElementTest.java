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
import java.util.Random;

import junit.framework.Assert;

import org.junit.Test;

/**
 * @author Yves Cuillerdier <yves@cuillerdier.net>
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

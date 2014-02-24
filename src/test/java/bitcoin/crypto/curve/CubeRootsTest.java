/**
 * Copyright 2014 Yves Cuillerdier.
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
public class CubeRootsTest implements ECCurve {

	@Test
	public void testCubeBase() {
		// We have P = 9*u + 7
		final BigInteger base = P.divide(BigInteger.valueOf(9L)).add(
				BigInteger.ONE);
		Assert.assertEquals(ECFieldElement.CUBE_BASE, base);
	}

	@Test
	public void testUnityCubeRoots() {
		// Check Unity cube roots
		Assert.assertEquals(ECFieldElement.ONE, ECFieldElement.UNITY_CUBEROOT_1
				.square().multiply(ECFieldElement.UNITY_CUBEROOT_1));
		Assert.assertEquals(ECFieldElement.ONE, ECFieldElement.UNITY_CUBEROOT_2
				.square().multiply(ECFieldElement.UNITY_CUBEROOT_2));
	}

	@Test
	public void testCubeRoot() {
		final ECFieldElement val = new ECFieldElement(new BigInteger(
				FIELD_SIZE, SECURE_RANDOM).mod(P));
		final ECFieldElement val3 = val.square().multiply(val);

		// cubeRoot may not be equals to val because we got one of the three
		// solutions!
		final ECFieldElement[] roots = val3.cubeRoot();
		if (roots.length != 3) {
			Assert.fail();
			return;
		}
		Assert.assertTrue(val.equals(roots[0]) || val.equals(roots[1])
				|| val.equals(roots[2]));
	}

	@Test
	public void testX3p7() {
		// Check X^3 + 7 = 0 don't have solutions
		final ECFieldElement val = new ECFieldElement(BigInteger.valueOf(7))
				.negate();

		final ECFieldElement[] roots = val.cubeRoot();

		Assert.assertEquals(0, roots.length);
	}
}

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
package bitcoin.crypto.utils;

import java.math.BigInteger;
import java.util.Random;

import junit.framework.Assert;

import org.junit.Test;

/**
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
@SuppressWarnings({ "nls", "static-method" })
public class BigIntegerUtilsTest {

	@Test
	public void test() {

		for (int i = 1; i <= 256; i++) {
			Assert.assertEquals(32, BigIntegerUtils
					.integerToBytes(new BigInteger(i, new Random())).length);
		}

		try {
			// more than 256 bits
			Assert.assertEquals(
					32,
					BigIntegerUtils
							.integerToBytes(new BigInteger(
									"10000000000000000000000000000000000000000000000000000000000000000",
									16)).length);
			Assert.fail("Should throws IllegalArgumentException");
		} catch (final IllegalArgumentException e) {
			// OK
		}

	}

}

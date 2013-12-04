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
package bitcoin.crypto.address;

import junit.framework.Assert;

import org.junit.Test;

/**
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
@SuppressWarnings({ "nls", "static-method" })
public class AddressTest {

	@Test
	public void testMainNetwork() {
		// Main network
		BitcoinAddress addr = null;
		try {
			addr = new BitcoinAddress("17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL");
		} catch (final AddressFormatException e) {
			Assert.fail(e.getMessage());
			return;
		}

		Assert.assertTrue(addr.isValid());
		Assert.assertTrue(addr.isProduction());
		Assert.assertFalse(addr.isTest());

		// Hash160
		Assert.assertEquals(BitcoinAddress.LENGTH, addr.getHash160().length);
	}

	@Test
	public void testTestNetwork() {
		// Test network
		BitcoinAddress addr = null;
		try {
			addr = new BitcoinAddress("n4eA2nbYqErp7H6jebchxAN59DmNpksexv");
		} catch (final AddressFormatException e) {
			Assert.fail(e.getMessage());
			return;
		}

		Assert.assertTrue(addr.isValid());
		Assert.assertFalse(addr.isProduction());
		Assert.assertTrue(addr.isTest());

		// Hash160
		Assert.assertEquals(BitcoinAddress.LENGTH, addr.getHash160().length);
	}
}

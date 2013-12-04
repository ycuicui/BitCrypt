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
package bitcoin.crypto.key;

import java.math.BigInteger;

import junit.framework.Assert;

import org.junit.Test;

import bitcoin.crypto.address.AddressFormatException;
import bitcoin.crypto.address.BitcoinAddress;

/**
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
@SuppressWarnings("static-method")
public class DumpedPrivateKeyTest {

	@Test
	public final void testProdCompressed() {
		doTest(true, true);
	}

	@Test
	public final void testProdNoCompressed() {
		doTest(true, false);
	}

	@Test
	public final void testTestCompressed() {
		doTest(false, true);
	}

	@Test
	public final void testTestNoCompressed() {
		doTest(false, false);
	}

	private static void doTest(final boolean prod, final boolean compressed) {
		final ECKey key = new ECKey();

		final DumpedPrivateKey dp1 = new DumpedPrivateKey(prod, key, compressed);
		final String dumped = dp1.toString();

		DumpedPrivateKey dp2;
		try {
			dp2 = new DumpedPrivateKey(prod, dumped);
		} catch (final AddressFormatException e) {
			Assert.fail(e.getMessage());
			return;
		}

		Assert.assertEquals(dp1, dp2);

		final ECKey key2 = dp2.getKey();
		Assert.assertEquals(key, key2);

		final BitcoinAddress addr1 = new BitcoinAddress(prod, key, compressed);
		final BitcoinAddress addr2 = dp2.getAddress();
		Assert.assertEquals(addr1, addr2);

		Assert.assertTrue(addr2.isProduction() == prod);
	}

	@Test
	public void testImportCompressedPrivKey() {
		final String address = "1L7S4no7372gqFp9YLRXcjYazvxNB7gD3j"; //$NON-NLS-1$
		final String encodePrivKey = "KwgV68eZay1uAfuuhz56Z5qkHnut75d9SfPRoqCDQ6SNUdQPHBQd"; //$NON-NLS-1$

		// Decode
		DumpedPrivateKey dp;
		try {
			dp = new DumpedPrivateKey(true, encodePrivKey);
		} catch (final AddressFormatException e) {
			Assert.fail();
			return;
		}
		Assert.assertEquals(address, dp.getAddress().toString());

		// Encode
		final BigInteger key = dp.getKey().getPrivateKey();
		if (key == null) {
			Assert.fail();
			return;
		}
		dp = new DumpedPrivateKey(true, new ECKey(key), true);
		Assert.assertEquals(encodePrivKey, dp.toString());
	}

	@Test
	public void testImportUnCompressedPrivKey() {
		final String address = "1GgNTrgohvfnrhCbpbqK1JzuiD75v4ujXy"; //$NON-NLS-1$
		final String encodePrivKey = "5HvMQpVuF3GcP8TVFivwjAFforNVoEjdMKDLDRWjEPXfrQRqW82"; //$NON-NLS-1$

		// Decode
		DumpedPrivateKey dp;
		try {
			dp = new DumpedPrivateKey(true, encodePrivKey);
		} catch (final AddressFormatException e) {
			Assert.fail();
			return;
		}
		Assert.assertEquals(address, dp.getAddress().toString());

		// Encode
		final BigInteger key = dp.getKey().getPrivateKey();
		if (key == null) {
			Assert.fail();
			return;
		}
		dp = new DumpedPrivateKey(true, new ECKey(key), false);
		Assert.assertEquals(encodePrivKey, dp.toString());
	}
}

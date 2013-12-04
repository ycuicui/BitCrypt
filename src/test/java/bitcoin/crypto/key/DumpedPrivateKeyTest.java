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
package bitcoin.crypto.key;

import java.math.BigInteger;

import junit.framework.Assert;

import org.junit.Test;

import bitcoin.crypto.address.AddressFormatException;
import bitcoin.crypto.address.BitcoinAddress;

/**
 * @author Yves Cuillerdier <yves@cuillerdier.net>
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

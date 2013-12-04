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
package bitcoin.crypto.address;

import junit.framework.Assert;

import org.junit.Test;

/**
 * @author Yves Cuillerdier <yves@cuillerdier.net>
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

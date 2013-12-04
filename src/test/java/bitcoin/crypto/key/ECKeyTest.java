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

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Yves Cuillerdier <yves@cuillerdier.net>
 */
@SuppressWarnings("static-method")
public class ECKeyTest {

	@Test
	public final void testECKey() {
		// Random key
		final ECKey key = new ECKey();
		Assert.assertNotNull(key.getPrivateKey());
		Assert.assertNotNull(key.getPublicKey());
		Assert.assertTrue(key.canSign());
	}

	@Test
	public final void testECKeyPub() {
		// Random key
		final ECKey key = new ECKey();

		// Key from public
		final ECKey key2 = new ECKey(key.getPublicKey());

		Assert.assertFalse(key2.canSign());
	}

	@Test
	public final void testECKeyPriv() {
		// Random key
		final ECKey key = new ECKey();
		final BigInteger priv = key.getPrivateKey();
		Assert.assertNotNull(priv);
		if (priv == null) {
			return;
		}

		// Key from private
		final ECKey key2 = new ECKey(priv);

		Assert.assertTrue(key2.canSign());
		Assert.assertEquals(key.getPublicKey(), key2.getPublicKey());
	}

	@Test
	public void testEquals() {
		final ECKey key1 = new ECKey();
		final ECKey key2 = new ECKey(key1.getPublicKey());

		Assert.assertEquals(key1.hashCode(), key2.hashCode());

		Assert.assertEquals(key1, key2);
	}
}

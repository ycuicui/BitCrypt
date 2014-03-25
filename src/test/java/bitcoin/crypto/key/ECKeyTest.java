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

import org.junit.Assert;
import org.junit.Test;

/**
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
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

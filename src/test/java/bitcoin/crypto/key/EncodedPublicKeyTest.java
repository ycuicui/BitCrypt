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

import junit.framework.Assert;

import org.junit.Test;

import bitcoin.crypto.curve.ECPoint;

/**
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
@SuppressWarnings("static-method")
public class EncodedPublicKeyTest {

	@Test
	public void testNotCompressed() {
		final ECKey key = new ECKey();

		final EncodedPublicKey encode = new EncodedPublicKey(key, false);

		Assert.assertFalse(encode.isCompressed());

		final ECPoint point = new ECPoint(encode.getBytes());
		Assert.assertEquals(key.getPublicKey(), point);
	}

	@Test
	public void testCompressed() {
		final ECKey key = new ECKey();

		final EncodedPublicKey encode = new EncodedPublicKey(key, true);

		Assert.assertTrue(encode.isCompressed());

		final ECPoint point = new ECPoint(encode.getBytes());
		Assert.assertEquals(key.getPublicKey(), point);
	}
}

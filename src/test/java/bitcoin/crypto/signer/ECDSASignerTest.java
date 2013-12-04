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
package bitcoin.crypto.signer;

import java.util.Random;

import org.junit.Assert;
import org.junit.Test;

import bitcoin.crypto.address.BitcoinAddress;
import bitcoin.crypto.curve.ECPoint;
import bitcoin.crypto.key.ECKey;

/**
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
@SuppressWarnings("nls")
public class ECDSASignerTest {

	private final Random RAND = new Random();

	@Test
	public final void testSignVerify() {
		// Signing key
		final ECKey key = new ECKey();

		// Message hash
		final byte[] hash = new byte[72];
		RAND.nextBytes(hash);

		// SIGN message
		final ECDSASignature signature = ECDSASigner.sign(hash, key);

		// Verify
		final boolean success = ECDSASigner.verifySignature(hash, signature,
				key.getPublicKey());

		Assert.assertTrue(success);
	}

	@Test
	public void testRecoverFromSignature() {

		final boolean prod = RAND.nextBoolean();

		// Signing key
		final ECKey key = new ECKey();

		// The associated address
		final BitcoinAddress address = new BitcoinAddress(prod, key, true);

		// Message hash
		final byte[] hash = new byte[72];
		RAND.nextBytes(hash);

		// SIGN message
		final ECDSASignature signature = ECDSASigner.sign(hash, key);

		// Try to recover public key
		final ECPoint q = ECDSASigner.recoverFromSignature(hash, signature,
				address);

		Assert.assertEquals(key.getPublicKey(), q);
	}

	@Test
	public void testAllRecoverFromSignatureAreValid() {

		// Signing key
		final ECKey key = new ECKey();

		// Message hash
		final byte[] hash = new byte[72];
		RAND.nextBytes(hash);

		// SIGN message
		final ECDSASignature signature = ECDSASigner.sign(hash, key);
		System.out.println("Signature: " + signature);

		// Recover all public key
		for (int i = 0; i < 4; i++) {
			// get one key
			final ECPoint q = ECDSASigner.recoverFromSignature(hash, signature,
					i);
			if (q == null) {
				continue;
			}
			// Verify
			final boolean success = ECDSASigner.verifySignature(hash,
					signature, q);
			// System.out.println("      Key: " + q
			// + (success ? " verify OK" : " fail"));
			Assert.assertTrue(success);
		}
	}
}

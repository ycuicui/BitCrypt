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
package bitcoin.crypto.signer;

import java.util.Random;

import org.junit.Assert;
import org.junit.Test;

import bitcoin.crypto.address.BitcoinAddress;
import bitcoin.crypto.curve.ECPoint;
import bitcoin.crypto.key.ECKey;

/**
 * @author Yves Cuillerdier <yves@cuillerdier.net>
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
			System.out.println("      Key: " + q
					+ (success ? " verify OK" : " fail"));
			Assert.assertTrue(success);
		}
	}
}

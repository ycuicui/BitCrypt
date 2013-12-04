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
import java.util.Date;

import jsr305.NonNull;
import jsr305.Nullable;
import bitcoin.crypto.curve.ECCurve;
import bitcoin.crypto.curve.ECPoint;

/**
 * Represents an elliptic curve public and (optionally) private key, usable for
 * digital signatures but not for encryption.
 * <p>
 * For elliptic curves, the private key {@code k} is an integer randomly
 * selected in the interval {@code [1, n-1]}. The public key is a point Q on the
 * curve where {@code Q = k * G}
 * <p>
 * Creating a new ECKey with the empty constructor will generate a new random
 * keypair. Other constructors can be used when you already have the public or
 * private parts. If you create a key with only the public part, you can check
 * signatures but not create them.
 * 
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
public class ECKey implements ECCurve {

	/**
	 * The private key is a secret number, known only to the person that
	 * generated it. A private key is essentially a randomly generated number.
	 * In Bitcoin, someone with the private key that corresponds to funds on the
	 * public ledger can spend the funds. In Bitcoin, a private key is a single
	 * unsigned 256 bit integer (32 bytes).
	 * <p>
	 * The private key could be null. In that case, we can only verify
	 * signatures not make them.
	 * <p>
	 * If defined, the private key is &gt; 0 and &lt; n
	 * <p>
	 * TODO: Security concern: change BigInteger to byte[] in order to be able
	 * to clear the private key from memory by zeroing the byte values. Having
	 * BigInteger, we can only dereference the field!
	 */
	@Nullable
	private final BigInteger priv;

	/**
	 * The public key is a number that corresponds to a private key, but does
	 * not need to be kept secret. A public key can be calculated from a private
	 * key, but not vice versa. A public key can be used to determine if a
	 * signature is genuine (in other words, produced with the proper key)
	 * without requiring the private key to be divulged.
	 * <p>
	 * For Bitcoin, the public key is a point on the elliptic curve.
	 */
	@NonNull
	private final ECPoint pub;

	/**
	 * Creation time of the key in seconds since the epoch, or zero if the key
	 * was deserialized from a version that did not have this field.
	 */
	private final long creationTimeSeconds;

	/**
	 * Generates an entirely new keypair.
	 */
	public ECKey() {
		BigInteger d;
		do {
			d = new BigInteger(256, SECURE_RANDOM);
		} while (!isValidPrivKey(d));

		priv = d;
		pub = G.multiply(d); // d<N so could not be O

		creationTimeSeconds = new Date().getTime() / 1000;
	}

	/**
	 * Creates an ECKey given the private key only. The public key is calculated
	 * from it.
	 * 
	 * @throws IllegalArgumentException
	 */
	public ECKey(@NonNull final BigInteger privKey) {
		if (!isValidPrivKey(privKey)) {
			throw new IllegalArgumentException("Invalid private key"); //$NON-NLS-1$
		}

		priv = privKey;
		pub = G.multiply(privKey); // privKey<N so could not be O

		creationTimeSeconds = 0;
	}

	/**
	 * Creates an ECKey given the public key only. The private key is not set.
	 * this ECKey cannot be used for signing, but could be used to verify
	 * signatures.
	 */
	public ECKey(@NonNull final ECPoint pubKey) {
		if (pubKey.isInfinity()) {
			throw new IllegalArgumentException("Public key could not be O"); //$NON-NLS-1$
		}
		priv = null;
		pub = pubKey;

		creationTimeSeconds = 0;
	}

	/**
	 * @return the public key as an ECPoint. This is not the infinity Point
	 */
	@NonNull
	public ECPoint getPublicKey() {
		return pub;
	}

	/**
	 * @return {@code true} if this key can receive money
	 */
	public boolean hasPrivateKey() {
		return priv != null;
	}

	/**
	 * @return the private key as a BigInteger
	 */
	@Nullable
	public BigInteger getPrivateKey() {
		return priv;
	}

	/**
	 * @returns whether this key could be used to sign messages or not.
	 */
	public boolean canSign() {
		return priv != null;
	}

	/**
	 * @return the creation time
	 */
	public long getCreationTimeSeconds() {
		return creationTimeSeconds;
	}

	@Override
	public boolean equals(final Object o) {
		if (this == o) {
			return true;
		}
		if (o == null || getClass() != o.getClass()) {
			return false;
		}

		final ECKey ecKey = (ECKey) o;
		return pub.equals(ecKey.pub);
	}

	@Override
	public int hashCode() {
		return pub.hashCode();
	}

	/**
	 * Check that the private key is &gt; 0 and &lt; n
	 * 
	 * @param privKey
	 *            integer to test
	 * @return true if the private key is &gt; 0 and &lt; n
	 */
	private static boolean isValidPrivKey(final BigInteger privKey) {
		return privKey.compareTo(BigInteger.ZERO) > 0
				&& privKey.compareTo(N) < 0;
	}
}

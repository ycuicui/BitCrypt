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

import jsr305.NonNull;
import bitcoin.crypto.curve.ECPoint;

/**
 * This is just a wrapper for a byte array representing an encoded public key
 * <p>
 * Public key is use to generate address. In Bitcoin, one could use either
 * compressed or uncompressed public key. Compressed public keys are 33 bytes,
 * consisting of a prefix either {@code 0x02} or {@code 0x03}, and a 256-bit
 * integer called {@code x}. The prefix of a compressed key allows for the
 * {@code y} value to be derived from the {@code x} value: {@code 0x02} if
 * {@code y} is even, {@code 0x03} if {@code y} is odd.
 * <p>
 * The older uncompressed keys are 65 bytes, consisting of constant prefix
 * {@code 0x04}, followed by two 256-bit integers called {@code x} and {@code y}
 * (2 * 32 bytes).
 * 
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
public class EncodedPublicKey {

	/**
	 * The encoded key. This is a 33 or 65 bytes byte array.
	 */
	@NonNull
	private final byte[] encoded;

	/**
	 * Create an encoded public key from a Key
	 * 
	 * @param key
	 *            the key to encode
	 * @param compressed
	 *            Whether the encoded key must be compressed
	 */
	public EncodedPublicKey(@NonNull final ECKey key, final boolean compressed) {
		// key is not null and != O
		this(key.getPublicKey(), compressed);
	}

	/**
	 * Create an encoded public key from a Point on a curve
	 * 
	 * @param point
	 *            the Point representing the public key
	 * @param compressed
	 *            Whether the encoded key must be compressed
	 */
	public EncodedPublicKey(@NonNull final ECPoint point,
			final boolean compressed) {
		// point is not null
		encoded = point.getEncoded(compressed);
	}

	/**
	 * @return {@code true} if the encoded key is compressed
	 */
	public boolean isCompressed() {
		return encoded.length == 33;
	}

	/**
	 * Return the bytes of the encoded key
	 * <p>
	 * The internal array is exposed! Don't modify it
	 * 
	 * @return the bytes of the encoded key
	 */
	@NonNull
	public byte[] getBytes() {
		return encoded;
	}
}

/**
 * Copyright 2011 Google Inc.
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
import java.util.Arrays;

import jsr305.NonNull;
import bitcoin.crypto.address.AddressFormatException;
import bitcoin.crypto.address.BitcoinAddress;
import bitcoin.crypto.address.VersionedChecksummedBytes;
import bitcoin.crypto.utils.BigIntegerUtils;

/**
 * Utility to imports or exports private keys in the form used by the Bitcoin
 * "dumpprivkey" command.
 * <p>
 * This is the private key bytes with a header byte and 4 checksum bytes at the
 * end. If there are 33 private key bytes instead of 32, then the last byte is a
 * discriminator value indicating that the corresponding address must be
 * generated using the compressed public key.
 */
public class DumpedPrivateKey extends VersionedChecksummedBytes {

	private static final int PROD_VERSION = 128;
	private static final int TEST_VERSION = 239;

	/**
	 * wether the dumped private key generate address using compressed public
	 * key or not.
	 */
	private final boolean compressed;

	/**
	 * Parses the given private key as created by the "dumpprivkey" Bitcoin C++
	 * RPC.
	 * 
	 * @param prodNetwork
	 *            {@code true} for production, {@code false} for testing
	 * @param encoded
	 *            The base58 encoded string.
	 * @throws AddressFormatException
	 *             If the string is invalid or the header byte doesn't match the
	 *             network params.
	 */
	public DumpedPrivateKey(final boolean prodNetwork, final String encoded)
			throws AddressFormatException {
		super(encoded);

		final int privateKeyHeader = prodNetwork ? PROD_VERSION : TEST_VERSION;
		if (version != privateKeyHeader) {
			throw new AddressFormatException("Mismatched version number: " //$NON-NLS-1$
					+ version + " vs " + privateKeyHeader); //$NON-NLS-1$
		}
		if (version != PROD_VERSION && version != TEST_VERSION) {
			throw new AddressFormatException("Invalid version number: " //$NON-NLS-1$
					+ version + ". Must be 128 or 239."); //$NON-NLS-1$
		}

		// Exported keys may add a '1' byte at end to signify other clients that
		// the adresse to be generated must be with the compressed form of the
		// public key.
		// This is just an artifact !!!
		if (bytes.length == 33 && bytes[32] == 1) {
			compressed = true;
			// Private key is the 32 first bytes
		} else if (bytes.length == 32) {
			compressed = false;
		} else {
			throw new AddressFormatException(
					"Wrong number of bytes for a private key, not 32 or 33"); //$NON-NLS-1$
		}
	}

	/**
	 * Prepare a private key to be dumped;
	 * <p>
	 * When exported to a file, consider to Crypt the file.
	 * 
	 * @param prodNetwork
	 *            {@code true} for production, {@code false} for testing
	 * @param key
	 *            the private key. Note we provide an ECKey, not a BigInteger to
	 *            ensure the value is >0 and <N
	 * @param comp
	 *            Whether the key is for a compressed public key
	 */
	public DumpedPrivateKey(final boolean prodNetwork, final ECKey key,
			final boolean comp) {
		this(prodNetwork, getKeyBytes(key), comp);
	}

	@NonNull
	private static byte[] getKeyBytes(final ECKey key) {
		final BigInteger priv = key.getPrivateKey();
		if (priv == null) {
			throw new IllegalArgumentException("Key has no private value"); //$NON-NLS-1$
		}
		return BigIntegerUtils.integerToBytes(priv);
	}

	/**
	 * Prepare a private key to be dumped;
	 * <p>
	 * When exported to a file, consider to Crypt the file.
	 * 
	 * @param prodNetwork
	 *            {@code true} for production, {@code false} for testing
	 * @param privBytes
	 *            the private key bytes. Must be 32 bytes long.
	 * @param comp
	 *            Whether the key is for a compressed public key
	 */
	public DumpedPrivateKey(final boolean prodNetwork,
			@NonNull final byte[] privBytes, final boolean comp) {
		super(prodNetwork ? PROD_VERSION : TEST_VERSION, new byte[comp ? 33
				: 32]);

		if (privBytes.length != 32) {
			throw new IllegalArgumentException("Bad length for private key"); //$NON-NLS-1$
		}

		compressed = comp;
		System.arraycopy(privBytes, 0, bytes, 0, 32);
		if (compressed) {
			bytes[32] = (byte) 0x01;
		}
	}

	/**
	 * Returns an ECKey created from this encoded private key.
	 */
	@NonNull
	public ECKey getKey() {
		byte[] b = bytes;
		if (b.length == 33 && b[32] == 1) {
			// Chop off the additional marker byte.
			b = Arrays.copyOf(b, 32);
		}
		return new ECKey(new BigInteger(1, b));
	}

	/**
	 * Return an Address corresponding to this encoded private key
	 * 
	 * @return Address corresponding to this encoded private key
	 */
	public BitcoinAddress getAddress() {
		return new BitcoinAddress(version == PROD_VERSION, getKey(), compressed);
	}
}

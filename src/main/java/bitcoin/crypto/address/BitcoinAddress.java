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

package bitcoin.crypto.address;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import jsr305.NonNull;
import jsr305.Nullable;
import bitcoin.crypto.curve.ECPoint;
import bitcoin.crypto.digest.RIPEMD160Digest;
import bitcoin.crypto.key.ECKey;

/**
 * An address is a RIPEMD160 hash of an addressable object (generally a public
 * key), therefore is always 160 bits or 20 bytes.
 * <p>
 * A Bitcoin address looks like [@code 1MsScoe2fTJoq4ZPdQgqyhgWeoNamYPevy} and
 * is derived from an elliptic curve public key plus a set of network
 * parameters. Not to be confused with a {@link PeerAddress} or
 * {@link AddressMessage} which are about network (TCP) addresses.
 * <p>
 * A standard address is built by taking the RIPE-MD160 hash of the public key
 * bytes, with a version prefix and a checksum suffix, then encoding it
 * textually as base58. The version prefix is used to both denote the network
 * for which the address is valid (see {@link NetworkParameters}, and also to
 * indicate how the bytes inside the address should be interpreted. Whilst
 * almost all addresses today are hashes of public keys, another (currently
 * unsupported type) can contain a hash of a script instead.
 * <p>
 * An address must be validated against a network type (test or production)
 * before using it on that network.
 * <p>
 * Notice that, due to the fact that the public key could be compressed or not,
 * the same private key could leads to two different address!
 */
public class BitcoinAddress extends VersionedChecksummedBytes {

	private static final int PROD_VERSION = 0;
	private static final int TEST_VERSION = 111;

	/**
	 * An address is a RIPEMD160 hash of some object (currently a public key),
	 * therefore is always 160 bits or 20 bytes.
	 */
	public static final int LENGTH = 20;

	/**
	 * {@code true} if this address is for a compressed public key.
	 * <p>
	 * This is null if the Address does not have a public key, for example an
	 * address used to send money.
	 */
	@Nullable
	private Boolean useCompressedKey;

	/**
	 * Construct an address for the needed network type and the given key.
	 * 
	 * @param prodNetwork
	 *            {@code true} for production, {@code false} for testing
	 * @param key
	 *            the public key used to create the address
	 * @param compressed
	 *            {@true} to use the compressed form of the public key
	 */
	public BitcoinAddress(final boolean prodNetwork, @NonNull final ECKey key,
			final boolean compressed) {
		this(prodNetwork, key.getPublicKey(), compressed);
	}

	/**
	 * Construct an address for the needed network type and the given public
	 * key.
	 * 
	 * @param prodNetwork
	 *            {@code true} for production, {@code false} for testing
	 * @param key
	 *            the public key used to create the address
	 * @param compressed
	 *            {@true} to use the compressed form of the public key
	 */
	public BitcoinAddress(final boolean prodNetwork,
			@NonNull final ECPoint key, final boolean compressed) {
		super(prodNetwork ? PROD_VERSION : TEST_VERSION, //
				sha256hash160(key.getEncoded(compressed)));
		useCompressedKey = Boolean.valueOf(compressed);
	}

	/**
	 * Construct an address for the needed network type and the given hash160.
	 * <p>
	 * Using directly the hash does not give any indication on the fact that the
	 * public key was compressed or not.
	 * 
	 * @param prodNetwork
	 *            {@code true} for production, {@code false} for testing
	 * @param hash
	 *            the hash160 used to create the address
	 */
	public BitcoinAddress(final boolean prodNetwork,
			@NonNull final byte[] hash160) {
		super(prodNetwork ? PROD_VERSION : TEST_VERSION, hash160);
		useCompressedKey = null;
	}

	/**
	 * Construct an address from the standard "human readable" form. Example:
	 * 
	 * <pre>
	 * new Address(&quot;17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL&quot;);
	 * </pre>
	 * 
	 * @param address
	 *            The textual form of the address, such as
	 *            "17kzeh4N8g49GFvdDzSf8PjaPfyoD1MndL"
	 * @throws AddressFormatException
	 *             if the given address doesn't parse or the checksum is invalid
	 */
	public BitcoinAddress(@NonNull final String address)
			throws AddressFormatException {
		super(address);
		useCompressedKey = null;
	}

	/**
	 * The (big endian) 20 byte hash that is the core of a Bitcoin address.
	 * <p>
	 * Notice that the hash160 of an address does not depends on the network
	 * type!
	 */
	@NonNull
	public byte[] getHash160() {
		return bytes.clone();
	}

	/**
	 * @return {@code true} if this address is for the production network.
	 * @see #isTest()
	 * @see #isValid()
	 */
	public boolean isProduction() {
		return version == PROD_VERSION;
	}

	/**
	 * @return {@code true} if this address is for the one of the test networks.
	 * @see #isProduction()
	 * @see #isValid()
	 */
	public boolean isTest() {
		return version == TEST_VERSION;
	}

	/**
	 * @return {@code true} if this address is for the production or one of the
	 *         test networks.
	 * @see #isProduction()
	 * @see #isTest()
	 */
	public boolean isValid() {
		return isProduction() || isTest();
	}

	/**
	 * @return {@code null} if the address has no associated public key, else
	 *         {@code Boolean.TRUE} if the address use a compressed public key
	 *         or {@code Boolean.FALSE} if the address use an uncompressed
	 *         public key
	 */
	@Nullable
	public Boolean useCompressedKey() {
		return useCompressedKey;
	}

	/**
	 * Set the useCompressedKey if the field is not set
	 * 
	 * @param val
	 */
	public void setUseCompressedKey(final Boolean val) {
		if (val == null) {
			useCompressedKey = val;
		}
	}

	/**
	 * Calculates RIPEMD160(SHA256(input)). This is the hash160 for the address.
	 * <p>
	 * Protected for test
	 */
	@NonNull
	static byte[] sha256hash160(@NonNull final byte[] input) {
		try {
			final byte[] sha256 = MessageDigest.getInstance("SHA-256").digest( //$NON-NLS-1$
					input);
			final RIPEMD160Digest dgst = new RIPEMD160Digest();
			return dgst.getDigest(sha256);
		} catch (final NoSuchAlgorithmException e) {
			throw new RuntimeException(e); // Cannot happen.
		}
	}
}

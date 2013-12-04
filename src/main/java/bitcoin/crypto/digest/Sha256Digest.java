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
package bitcoin.crypto.digest;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import jsr305.NonNull;

/**
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
public class Sha256Digest {

	private static final MessageDigest SHA_DIGEST;
	static {
		try {
			SHA_DIGEST = MessageDigest.getInstance("SHA-256"); //$NON-NLS-1$
		} catch (final NoSuchAlgorithmException e) {
			throw new RuntimeException(e); // Can't happen.
		}
	}

	private Sha256Digest() {
		// Static
	}

	/**
	 * Calculates the (one-time) hash of contents. The resulting hash is in
	 * little endian form.
	 */
	@NonNull
	public static byte[] digest(@NonNull final byte[] contents) {
		synchronized (SHA_DIGEST) {
			SHA_DIGEST.reset();
			SHA_DIGEST.update(contents);
			return SHA_DIGEST.digest();
		}
	}

	/**
	 * Calculates the SHA-256 hash of the given byte range, and then hashes the
	 * resulting hash again. This is standard procedure in Bitcoin. The
	 * resulting hash is in little endian form.
	 */
	@NonNull
	public static byte[] doubleDigest(@NonNull final byte[] input,
			final int offset, final int length) {
		synchronized (SHA_DIGEST) {
			SHA_DIGEST.reset();
			SHA_DIGEST.update(input, offset, length);
			final byte[] first = SHA_DIGEST.digest();
			return SHA_DIGEST.digest(first);
		}
	}

	/**
	 * Calculates the hash of the hash of the two contents. This is used to
	 * compute the Merkle tree in blocks. The resulting hash is in little endian
	 * form.
	 */
	@NonNull
	public static byte[] doubleDigest(@NonNull final byte[] contents1,
			@NonNull final byte[] contents2) {
		synchronized (SHA_DIGEST) {
			SHA_DIGEST.reset();
			SHA_DIGEST.update(contents1);
			SHA_DIGEST.update(contents2);
			final byte[] first = SHA_DIGEST.digest();
			return SHA_DIGEST.digest(first);
		}
	}
}

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

import java.util.Arrays;

import jsr305.NonNull;
import bitcoin.crypto.digest.Sha256Digest;

/**
 * In Bitcoin the following format is often used to represent some type of key:
 * 
 * <pre>
 * [one version byte] [data bytes] [4 checksum bytes]
 * </pre>
 * 
 * and the result is then Base58 encoded. This format is used for addresses, and
 * private keys exported using the dumpprivkey command.
 */
public class VersionedChecksummedBytes {

	/**
	 * The version byte
	 */
	protected final int version;

	/**
	 * The data bytes (exclude version byte and checksum)
	 * <p>
	 * Array values MUST not be modified
	 */
	@NonNull
	protected final byte[] bytes;

	protected VersionedChecksummedBytes(@NonNull final String encoded)
			throws AddressFormatException {
		// Decode input
		byte tmp[] = Base58.decode(encoded);

		// Check
		final int tmpLength = tmp.length;
		if (tmpLength < 5) {
			throw new AddressFormatException("Input to short"); //$NON-NLS-1$
		}
		version = tmp[0] & 0xFF;
		bytes = new byte[tmpLength - 5];
		System.arraycopy(tmp, 1, bytes, 0, tmpLength - 5);

		final byte[] checksum = new byte[4];
		System.arraycopy(tmp, tmpLength - 4, checksum, 0, 4);
		tmp = Sha256Digest.doubleDigest(tmp, 0, tmpLength - 4);
		for (int i = 0; i < 4; i++) {
			if (checksum[i] != tmp[i]) {
				throw new AddressFormatException("Checksum does not validate"); //$NON-NLS-1$
			}
		}
	}

	protected VersionedChecksummedBytes(final int v, @NonNull final byte[] b) {
		if (v < 0 || v > 255) {
			throw new IllegalArgumentException();
		}
		version = v;
		bytes = b;
	}

	/**
	 * Returns the "version" or "header" byte: the first byte of the data. This
	 * is used to disambiguate what the contents apply to, for example, which
	 * network the key or address is valid on.
	 * 
	 * @return A positive number between 0 and 255.
	 */
	public int getVersion() {
		return version;
	}

	@Override
	public int hashCode() {
		return Arrays.hashCode(bytes);
	}

	@Override
	public boolean equals(final Object o) {
		if (!(o instanceof VersionedChecksummedBytes)) {
			return false;
		}
		final VersionedChecksummedBytes vcb = (VersionedChecksummedBytes) o;
		return Arrays.equals(vcb.bytes, bytes);
	}

	@Override
	@NonNull
	public String toString() {
		// A stringified buffer is:
		// 1 byte version + data bytes + 4 bytes check code (a truncated hash)
		final byte[] addressBytes = new byte[1 + bytes.length + 4];
		addressBytes[0] = (byte) version;
		System.arraycopy(bytes, 0, addressBytes, 1, bytes.length);
		final byte[] check = Sha256Digest.doubleDigest(addressBytes, 0,
				bytes.length + 1);
		System.arraycopy(check, 0, addressBytes, bytes.length + 1, 4);
		return Base58.encode(addressBytes);
	}
}

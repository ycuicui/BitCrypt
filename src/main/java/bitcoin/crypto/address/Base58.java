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

import java.io.UnsupportedEncodingException;

import jsr305.NonNull;

/**
 * Base58 is a way to encode Bitcoin addresses as numbers and letters. Note that
 * this is not the same base58 as used by Flickr, which you may see reference to
 * around the internet.
 * <p>
 * You may instead wish to work with {@link VersionedChecksummedBytes}, which
 * adds support for testing the prefix and suffix bytes commonly found in
 * addresses.
 * <p>
 * Satoshi says: why base-58 instead of standard base-64 encoding?
 * <ul>
 * <li>Don't want 0OIl characters that look the same in some fonts and could be
 * used to create visually identical looking account numbers.</li>
 * <li>A string with non-alphanumeric characters is not as easily accepted as an
 * account number.</li>
 * <li>E-mail usually won't line-break if there's no punctuation to break at.</li>
 * <li>Doubleclicking selects the whole number as one word if it's all
 * alphanumeric.</li>
 * </ul>
 */
public class Base58 {

	public static final char[] ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz" //$NON-NLS-1$
	.toCharArray();

	private static final int[] INDEXES = new int[128];
	static {
		for (int i = 0; i < INDEXES.length; i++) {
			INDEXES[i] = -1;
		}
		for (int i = 0; i < ALPHABET.length; i++) {
			INDEXES[ALPHABET[i]] = i;
		}
	}

	private Base58() {
		// Static
	}

	/** Encodes the given bytes in base58. No checksum is appended. */
	@NonNull
	public static String encode(@NonNull final byte[] inputByte) {
		if (inputByte.length == 0) {
			return ""; //$NON-NLS-1$
		}
		final byte[] input = copyOfRange(inputByte, 0, inputByte.length);
		final int inputLength = inputByte.length;
		// Count leading zeroes.
		int zeroCount = 0;
		while (zeroCount < inputLength && input[zeroCount] == 0) {
			++zeroCount;
		}
		// The actual encoding.
		final int tempLength = inputLength * 2;
		final byte[] temp = new byte[tempLength];

		int j = tempLength;
		int startAt = zeroCount;
		while (startAt < inputLength) {
			final byte mod = divmod58(input, startAt);
			if (input[startAt] == 0) {
				++startAt;
			}
			temp[--j] = (byte) ALPHABET[mod];
		}

		// Strip extra '1' if there are some after decoding.
		while (j < tempLength && temp[j] == ALPHABET[0]) {
			++j;
		}
		// Add as many leading '1' as there were leading zeros.
		while (--zeroCount >= 0) {
			temp[--j] = (byte) ALPHABET[0];
		}

		final byte[] output = copyOfRange(temp, j, tempLength);
		try {
			return new String(output, "US-ASCII"); //$NON-NLS-1$
		} catch (final UnsupportedEncodingException e) {
			throw new RuntimeException(e); // Cannot happen.
		}
	}

	/**
	 * Decode the input encoded in base58 as an array of bytes
	 * 
	 * @param input
	 *            value encoded in base58
	 * @return decoded value
	 * @throws AddressFormatException
	 *             if the input is not base 58
	 */
	public static byte[] decode(@NonNull final String input)
			throws AddressFormatException {
		final int inputLength = input.length();

		if (inputLength == 0) {
			return new byte[0];
		}

		// Transform the String to a base58 byte sequence
		final byte[] input58 = new byte[inputLength];
		for (int i = 0; i < inputLength; ++i) {
			final char c = input.charAt(i);

			int digit58 = -1;
			if (c >= 0 && c < 128) {
				digit58 = INDEXES[c];
			}
			if (digit58 < 0) {
				throw new AddressFormatException("Illegal character " + c //$NON-NLS-1$
						+ " at " + i); //$NON-NLS-1$
			}

			input58[i] = (byte) digit58;
		}

		// Count leading zeroes
		int zeroCount = 0;
		while (zeroCount < inputLength && input58[zeroCount] == 0) {
			++zeroCount;
		}

		// The encoding
		final byte[] temp = new byte[inputLength];
		int j = inputLength;

		int startAt = zeroCount;
		while (startAt < inputLength) {
			final byte mod = divmod256(input58, startAt);
			if (input58[startAt] == 0) {
				++startAt;
			}

			temp[--j] = mod;
		}

		// Do no add extra leading zeroes, move j to first non null byte.
		while (j < temp.length && temp[j] == 0) {
			++j;
		}

		return copyOfRange(temp, j - zeroCount, temp.length);
	}

	/**
	 * number -> number / 58, returns number % 58
	 */
	private static byte divmod58(final byte[] number, final int startAt) {
		int remainder = 0;
		for (int i = startAt; i < number.length; i++) {
			final int digit256 = number[i] & 0xFF;
			final int temp = remainder * 256 + digit256;

			number[i] = (byte) (temp / 58);

			remainder = temp % 58;
		}

		return (byte) remainder;
	}

	/**
	 * number -> number / 256, returns number % 256
	 */
	private static byte divmod256(final byte[] number58, final int startAt) {
		int remainder = 0;
		for (int i = startAt; i < number58.length; i++) {
			final int digit58 = number58[i] & 0xFF;
			final int temp = remainder * 58 + digit58;

			number58[i] = (byte) (temp / 256);

			remainder = temp % 256;
		}

		return (byte) remainder;
	}

	private static byte[] copyOfRange(final byte[] source, final int from,
			final int to) {
		final byte[] range = new byte[to - from];
		System.arraycopy(source, from, range, 0, range.length);

		return range;
	}
}

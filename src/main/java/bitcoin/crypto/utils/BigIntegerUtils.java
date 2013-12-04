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
package bitcoin.crypto.utils;

import java.math.BigInteger;

import jsr305.NonNull;

/**
 * 
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
public class BigIntegerUtils {

	private BigIntegerUtils() {
		// Static
	}

	/**
	 * Return the integer converted to an exactly 32 bytes array
	 * <p>
	 * The regular {@link java.math.BigInteger#toByteArray()} method isn't quite
	 * what we often need: it appends a leading zero to indicate that the number
	 * is positive and may need padding.
	 * 
	 * @param s
	 *            integer to convert to byte array
	 * @return 32 bytes array of the integer
	 */
	@NonNull
	public static byte[] integerToBytes(@NonNull final BigInteger s) {
		final byte[] bytes = s.toByteArray();
		if (bytes.length == 32) {
			return bytes;
		}

		if (bytes.length < 32) {
			final byte[] tmp = new byte[32];
			System.arraycopy(bytes, 0, tmp, 32 - bytes.length, bytes.length);
			return tmp;
		}

		// Sometime, BigInteger.toByteArray return an extra 0x00
		if (bytes.length == 33 && bytes[0] == 0) {
			final byte[] tmp = new byte[32];
			System.arraycopy(bytes, 1, tmp, 0, 32);
			return tmp;
		}

		throw new IllegalArgumentException("BigInteger " + s + " too large"); //$NON-NLS-1$ //$NON-NLS-2$
	}
}

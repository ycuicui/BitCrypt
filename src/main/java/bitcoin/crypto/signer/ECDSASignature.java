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

import java.math.BigInteger;

import jsr305.NonNull;
import bitcoin.crypto.curve.ECCurve;

/**
 * Groups the two components that make up a signature.
 * 
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
public class ECDSASignature {

	/** The two components of the signature. */
	@NonNull
	private final BigInteger r;
	@NonNull
	private final BigInteger s;

	/**
	 * Constructs a signature with the given components.
	 * <p>
	 * The signature components are not checked
	 */
	public ECDSASignature(@NonNull final BigInteger vr,
			@NonNull final BigInteger vs) {
		r = vr;
		s = vs;
	}

	@NonNull
	public final BigInteger getR() {
		return r;
	}

	@NonNull
	public final BigInteger getS() {
		return s;
	}

	/**
	 * @return {@code true} if both components look valid i.e. are in the range
	 *         [1, n-1]
	 */
	public boolean isValid() {
		if (r.compareTo(BigInteger.ZERO) <= 0 || r.compareTo(ECCurve.N) >= 0) {
			return false;
		}
		if (s.compareTo(BigInteger.ZERO) <= 0 || s.compareTo(ECCurve.N) >= 0) {
			return false;
		}
		return true;
	}

	@SuppressWarnings("nls")
	@Override
	public String toString() {
		return "[" + r + ", " + s + "]";
	}
}

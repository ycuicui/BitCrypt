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
package bitcoin.crypto.curve;

import java.math.BigInteger;

import jsr305.NonNull;
import jsr305.Nullable;

/**
 * Unmutable element over the field of the bitcoin {@link ECCurve elliptic
 * curve}.
 * 
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
public class ECFieldElement implements ECCurve {

	@NonNull
	public final BigInteger value;

	public ECFieldElement(@NonNull final BigInteger val) {
		value = val;
		if (value.compareTo(P) >= 0) {
			throw new IllegalArgumentException(
					"Value too large in field element"); //$NON-NLS-1$
		}
	}

	@NonNull
	public BigInteger toBigInteger() {
		return value;
	}

	@NonNull
	public ECFieldElement add(@NonNull final ECFieldElement b) {
		return new ECFieldElement(value.add(b.value).mod(P));
	}

	@NonNull
	public ECFieldElement subtract(@NonNull final ECFieldElement b) {
		return new ECFieldElement(value.subtract(b.value).mod(P));
	}

	@NonNull
	public ECFieldElement multiply(@NonNull final ECFieldElement b) {
		return new ECFieldElement(value.multiply(b.value).mod(P));
	}

	@NonNull
	public ECFieldElement divide(@NonNull final ECFieldElement b) {
		return new ECFieldElement(value.multiply(b.value.modInverse(P)).mod(P));
	}

	@NonNull
	public ECFieldElement negate() {
		return new ECFieldElement(value.negate().mod(P));
	}

	@NonNull
	public ECFieldElement square() {
		return new ECFieldElement(value.multiply(value).mod(P));
	}

	@NonNull
	public ECFieldElement invert() {
		return new ECFieldElement(value.modInverse(P));
	}

	/**
	 * return a sqrt root - the routine verifies that the calculation returns
	 * the right value - if none exists it returns null.
	 */
	@Nullable
	public ECFieldElement sqrt() {

		// for bitcoin EC, p mod 4 == 3
		// If p = 4u +3, z = g^(u+1)
		final ECFieldElement z = new ECFieldElement(value.modPow(P
				.shiftRight(2).add(BigInteger.ONE), P));

		return z.square().equals(this) ? z : null;
	}

	@Override
	public boolean equals(final Object other) {
		if (other == this) {
			return true;
		}

		if (!(other instanceof ECFieldElement)) {
			return false;
		}

		final ECFieldElement o = (ECFieldElement) other;
		return value.equals(o.value);
	}

	@Override
	public int hashCode() {
		return value.hashCode();
	}

	@Override
	public String toString() {
		return value.toString();
	}
}

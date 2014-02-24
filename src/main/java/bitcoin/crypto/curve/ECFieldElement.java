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
import bitcoin.crypto.Incubation;

/**
 * Unmutable element over the field of the bitcoin {@link ECCurve elliptic
 * curve}.
 * 
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
public class ECFieldElement implements ECCurve {

	// Base for square root computation
	// As P = 4*u + 3, One square root of a is a^(u+1)
	static final BigInteger SQR_BASE = new BigInteger(
			"3fffffffffffffffffffffffffffffffffffffffffffffffffffffffbfffff0c", 16); //$NON-NLS-1$

	// Base for cube roots computation
	// As P = 9*u + 7, One cube root of a is a^(u+1)
	// package visibility for testing
	static final BigInteger CUBE_BASE = new BigInteger(
			"1c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c71c555554e9", 16); //$NON-NLS-1$

	// Cubic unity roots : (x^3-1)=(x-1)(x-X1)(x-X2)
	static final ECFieldElement UNITY_CUBEROOT_1 = new ECFieldElement(
			new BigInteger(
					"851695d49a83f8ef919bb86153cbcb16630fb68aed0a766a3ec693d68e6afa40", 16)); //$NON-NLS-1$
	static final ECFieldElement UNITY_CUBEROOT_2 = new ECFieldElement(
			new BigInteger(
					"7ae96a2b657c07106e64479eac3434e99cf0497512f58995c1396c28719501ee", 16)); //$NON-NLS-1$

	// Some useful values
	public static final ECFieldElement ZERO = new ECFieldElement(
			BigInteger.ZERO);
	public static final ECFieldElement ONE = new ECFieldElement(BigInteger.ONE);

	@NonNull
	public final BigInteger value;

	public ECFieldElement(long val) {
		this(BigInteger.valueOf(val));
	}

	public ECFieldElement(@NonNull final BigInteger val) {
		if (val.compareTo(BigInteger.ZERO) < 0) {
			throw new IllegalArgumentException(
					"Negative value  in field element"); //$NON-NLS-1$
		}
		if (val.compareTo(P) >= 0) {
			throw new IllegalArgumentException(
					"Value too large in field element"); //$NON-NLS-1$
		}
		value = val;
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
	public ECFieldElement pow(BigInteger exp) {
		return new ECFieldElement(value.modPow(exp, P));
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
		final ECFieldElement z = pow(SQR_BASE);

		return z.square().equals(this) ? z : null;
	}

	/**
	 * Compute the cube roots of the element.
	 * <p>
	 * For the Bitcoin field, not all elements have cube roots. Generally, an
	 * element have 0 or 3 roots!
	 * <p>
	 * Theory<br>
	 * ------
	 * <p>
	 * In Bitcoin P=9u+7 and x^3-1=(x-1)(x-X1)*(x-X2)
	 * <p>
	 * Then (a^(3u+2))^3-1 = 0 = (a^(3u+2) -1) (a^(3u+2) - X1) (a^(3u+2) - X2)
	 * <p>
	 * Notice that X1 and X2 are not cubes then if a^(3u+2) != 1, a don't have
	 * cube roots.
	 * <p>
	 * If a is such that a^(3u+2) = 1 ( = a^((P-1)/3) ) then:<br>
	 * a*a^(3u+2) = (a^(u+1))^3 = a and a^(u+1) is one of the three roots.
	 * 
	 * @return Array of the cube roots. The length of the array could be 0 or 3.
	 */
	@Incubation
	@NonNull
	public ECFieldElement[] cubeRoot() {
		final ECFieldElement cr = pow(CUBE_BASE);
		if (!cr.square().multiply(cr).equals(this)) {
			return new ECFieldElement[0];
		}

		return new ECFieldElement[] { cr, cr.multiply(UNITY_CUBEROOT_1),
				cr.multiply(UNITY_CUBEROOT_2) };
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

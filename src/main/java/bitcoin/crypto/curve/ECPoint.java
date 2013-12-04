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
import bitcoin.crypto.utils.BigIntegerUtils;

/**
 * Unmutable class for points on the bitcoin {@link ECCurve elliptic curve}.
 * 
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
public class ECPoint implements ECCurve {

	@NonNull
	private static final ECFieldElement TWO = new ECFieldElement(
			BigInteger.valueOf(2));
	@NonNull
	private static final ECFieldElement THREE = new ECFieldElement(
			BigInteger.valueOf(3));

	// Only null for infinity
	@Nullable
	private final ECFieldElement x;

	// Only null for infinity
	@Nullable
	private final ECFieldElement y;

	/**
	 * Create the infinity point
	 */
	ECPoint() {
		x = null;
		y = null;
	}

	/**
	 * Create a point from the {@code x,y} coordinate.
	 * <p>
	 * We do not check that the point is effectively on the curve
	 * 
	 * @param vx
	 *            affine x co-ordinate
	 * @param vy
	 *            affine y co-ordinate
	 */
	public ECPoint(@NonNull final ECFieldElement vx,
			@NonNull final ECFieldElement vy) {
		x = vx;
		y = vy;
	}

	/**
	 * Create a point from the {@code x} coordinate. Given the x value of a
	 * point, there are two possible {@code y} values. The {@code even}
	 * parameter is used to select the desired {@code y} value.
	 * <p>
	 * If {@code x} is random, there a 0.5 probability that there exists a point
	 * on the curve.
	 * 
	 * @param vx
	 *            affine x co-ordinate
	 * @param even
	 *            {@true} to select the even {@code y} value
	 * @throws IllegalArgumentException
	 *             if the x coordinate is not the one of point on the curve
	 */
	public ECPoint(@NonNull final BigInteger vx, final boolean even) {
		x = new ECFieldElement(vx);
		ECFieldElement yf = x.multiply(x.square()).add(B).sqrt();
		// if we can't find a sqrt we haven't got a point on the curve
		if (yf == null) {
			throw new IllegalArgumentException("Invalid x coordinate"); //$NON-NLS-1$
		}
		if (yf.toBigInteger().testBit(0) == even) {
			yf = new ECFieldElement(P.subtract(yf.toBigInteger()));
		}
		y = yf;
	}

	/**
	 * Create a point from its ASN.1 encoding. The point could be encoded in
	 * compressed or uncompressed form.
	 * <p>
	 * We do not check that the point is effectively on the curve.
	 * <p>
	 * Compressed points are 33 bytes, consisting of a prefix either
	 * {@code 0x02} or {@code 0x03}, and a 256-bit integer called {@code x}. The
	 * prefix of a compressed key allows for the {@code y} value to be derived
	 * from the {@code x} value: {@code 0x02} if {@code y} is even, {@code 0x03}
	 * if {@code y} is odd.
	 * <p>
	 * The uncompressed points are 65 bytes, consisting of constant prefix
	 * {@code 0x04}, followed by two 256-bit integers called {@code x} and
	 * {@code y} (2 * 32 bytes).
	 * <p>
	 * The infinity point is encode as a single byte {@code 0x00}
	 * 
	 * @param encoded
	 *            the encoded bytes of the point
	 * @throws IllegalArgumentException
	 */
	public ECPoint(@NonNull final byte[] encoded) {
		switch (encoded[0]) {
		// infinity
		case 0x00:
			if (encoded.length != 1) {
				throw new IllegalArgumentException("Invalid point encoding"); //$NON-NLS-1$
			}

			x = null;
			y = null;
			break;
		// compressed
		case 0x02:
		case 0x03:
			if (encoded.length != 33) {
				throw new IllegalArgumentException(
						"Invalid compressed point encoding"); //$NON-NLS-1$
			}

			final byte[] bytes = new byte[32];
			System.arraycopy(encoded, 1, bytes, 0, 32);

			final ECPoint pt = new ECPoint(new BigInteger(1, bytes),
					encoded[0] == 0x02);
			x = pt.x;
			y = pt.y;
			break;
		// uncompressed
		case 0x04:
			if (encoded.length != 65) {
				throw new IllegalArgumentException(
						"Invalid uncompressed point encoding"); //$NON-NLS-1$
			}

			final byte[] xEnc = new byte[32];
			final byte[] yEnc = new byte[32];

			System.arraycopy(encoded, 1, xEnc, 0, 32);
			System.arraycopy(encoded, 33, yEnc, 0, 32);

			x = new ECFieldElement(new BigInteger(1, xEnc));
			y = new ECFieldElement(new BigInteger(1, yEnc));
			break;
		default:
			throw new IllegalArgumentException(
					"Invalid point encoding prefix: 0x" //$NON-NLS-1$
							+ Integer.toString(encoded[0] & 0xff, 16));
		}
	}

	@Nullable
	public final ECFieldElement getX() {
		return x;
	}

	@Nullable
	public final ECFieldElement getY() {
		return y;
	}

	public boolean isInfinity() {
		return x == null && y == null;
	}

	@NonNull
	public ECPoint add(@NonNull final ECPoint b) {
		if (isInfinity()) {
			return b;
		}

		if (b.isInfinity()) {
			return this;
		}

		// Check if b = this or b = -this
		if (x.equals(b.x)) {
			if (y.equals(b.y)) {
				// this = b, i.e. this must be doubled
				return twice();
			}

			// this = -b, i.e. the result is the point at infinity
			return O;
		}

		final ECFieldElement gamma = b.y.subtract(y).divide(b.x.subtract(x));

		final ECFieldElement x3 = gamma.square().subtract(x).subtract(b.x);
		final ECFieldElement y3 = gamma.multiply(x.subtract(x3)).subtract(y);

		return new ECPoint(x3, y3);
	}

	@NonNull
	public ECPoint negate() {
		if (isInfinity()) {
			return O;
		}
		return new ECPoint(x, y.negate());
	}

	/**
	 * Implementation notes: For the Bitcoin curve, there is no point for which
	 * y = 0
	 */
	@NonNull
	public ECPoint twice() {
		if (isInfinity()) {
			// Twice identity element (point at infinity) is identity
			return this;
		}

		// This test is ommitted for the Bitcoin EC!
		// if (y.toBigInteger().signum() == 0) {
		// // if y1 == 0, then (x1, y1) == (x1, -y1)
		// // and hence this = -this and thus 2(x1, y1) == infinity
		// return O;
		// }

		final ECFieldElement gamma = x.square().multiply(THREE)
				.divide(y.multiply(TWO));

		final ECFieldElement x3 = gamma.square().subtract(x.multiply(TWO));
		final ECFieldElement y3 = gamma.multiply(x.subtract(x3)).subtract(y);

		return new ECPoint(x3, y3);
	}

	/**
	 * Multiplies this <code>ECPoint</code> by the given number.
	 * <p>
	 * Multiplies the <code>ECPoint p</code> by <code>k</code>, i.e.
	 * <code>p</code> is added <code>k</code> times to itself. *
	 * 
	 * @param k
	 *            The multiplicator.
	 * @return <code>k * this</code>.
	 * 
	 *         D.3.2 pg 101
	 * @see spongycastle.math.ec.ECMultiplier#multiply(bitcoin.crypto.curve.ECPoint,
	 *      java.math.BigInteger)
	 */
	@NonNull
	public ECPoint multiply(@NonNull final BigInteger k) {
		if (k.signum() < 0) {
			throw new IllegalArgumentException(
					"The multiplicator cannot be negative"); //$NON-NLS-1$
		}

		if (isInfinity()) {
			return this;
		}

		if (k.signum() == 0) {
			return O;
		}

		// TODO Probably should try to add this
		// BigInteger e = k.mod(n);
		final BigInteger h = k.multiply(BigInteger.valueOf(3));

		final ECPoint neg = negate();
		ECPoint r = this;

		for (int i = h.bitLength() - 2; i > 0; --i) {
			r = r.twice();

			final boolean hBit = h.testBit(i);
			final boolean eBit = k.testBit(i);

			if (hBit != eBit) {
				r = r.add(hBit ? this : neg);
			}
		}

		return r;
	}

	/**
	 * return the field element encoded with/without point compression.
	 * <p>
	 * Result has length 1 (infinity), 33 (compressed key) or 65 (uncompressed
	 * key)!
	 */
	@NonNull
	public byte[] getEncoded(final boolean withCompression) {
		if (isInfinity()) {
			return new byte[1]; // [ 0x00 ]
		}

		// 32 bytes
		final byte[] vx = BigIntegerUtils.integerToBytes(x.toBigInteger());
		byte[] bytes;
		if (withCompression) {
			bytes = new byte[33];
			if (y.toBigInteger().testBit(0)) {
				bytes[0] = 0x03;
			} else {
				bytes[0] = 0x02;
			}
			System.arraycopy(vx, 0, bytes, 1, 32);

		} else {

			// 32 bytes
			final byte[] vy = BigIntegerUtils.integerToBytes(y.toBigInteger());
			bytes = new byte[65];

			bytes[0] = 0x04;
			System.arraycopy(vx, 0, bytes, 1, 32);
			System.arraycopy(vy, 0, bytes, 33, 32);
		}
		return bytes;
	}

	@Override
	public int hashCode() {
		final int prime = 31;
		int result = 1;
		result = prime * result + (x == null ? 0 : x.hashCode());
		result = prime * result + (y == null ? 0 : y.hashCode());
		return result;
	}

	@Override
	public boolean equals(final Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null) {
			return false;
		}
		if (getClass() != obj.getClass()) {
			return false;
		}
		final ECPoint other = (ECPoint) obj;
		if (isInfinity()) {
			return other.isInfinity();
		}
		if (other.isInfinity()) {
			return false;
		}
		// x!=null && y!=null
		return x.equals(other.x) && y.equals(other.y);
	}

	@SuppressWarnings("nls")
	@Override
	public String toString() {
		if (isInfinity()) {
			return "Infinity";
		}

		final StringBuilder sb = new StringBuilder();
		sb.append("[").append(x).append(", ").append(y).append("]");
		return sb.toString();
	}
}

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
import jsr305.Nullable;
import bitcoin.crypto.address.BitcoinAddress;
import bitcoin.crypto.curve.ECCurve;
import bitcoin.crypto.curve.ECFieldElement;
import bitcoin.crypto.curve.ECPoint;
import bitcoin.crypto.key.ECKey;

/**
 * Utilities to sign or verify messages
 * <p>
 * The ECDSA algorithm supports <i>key recovery</i> in which a signature can be
 * reversed to find the public key used to calculate it. This can be convenient
 * when you have a message and a signature and want to find out who signed it,
 * rather than requiring the user to provide the expected identity.
 * 
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
public class ECDSASigner implements ECCurve {

	private ECDSASigner() {
		// static
	}

	/**
	 * Produce the signature of the given hash of the message
	 * 
	 * @param hash
	 *            Hash of the data to verify.
	 * @param key
	 *            private/public key
	 * @return the signature
	 * @throws IllegalArgumentException
	 */
	public static ECDSASignature sign(@NonNull final byte[] hash,
			@NonNull final ECKey key) {
		final BigInteger d = key.getPrivateKey();
		if (d == null) {
			throw new IllegalArgumentException(
					"A private key is required to sign a message"); //$NON-NLS-1$
		}

		// 1. Calculate e = HASH(message)
		// 2. and Let z be the n.bitLength() leftmost bits of e.
		final BigInteger z = calculateZ(hash);

		BigInteger r = BigInteger.ZERO;
		BigInteger s = BigInteger.ZERO;
		do {
			BigInteger k;
			do {
				// 3. Select a random integer k in the interval [1, n-1].
				do {
					k = new BigInteger(256, SECURE_RANDOM);
				} while (k.equals(BigInteger.ZERO) || k.compareTo(N) >= 0);

				// 4. Calculate the curve point u(x,y)=k*G
				final ECPoint u = G.multiply(k);

				// 5. Calculate r=x % n. If r==0, go back to step 3.
				final ECFieldElement vx = u.getX();
				if (vx != null) {
					r = vx.toBigInteger().mod(N);
				}
			} while (r.equals(BigInteger.ZERO));

			// 6. Calculate s = k^-1(z+r d). if s==0, go back to step 3.
			s = k.modInverse(N).multiply(z.add(d.multiply(r))).mod(N);
		} while (s.equals(BigInteger.ZERO));
		return new ECDSASignature(r, s);
	}

	/**
	 * return true if the value r and s represent an ECDSA signature for the
	 * passed hash of the message (for standard DSA the hash should be a SHA-1
	 * hash of the real message to be verified).
	 * 
	 * @param hash
	 *            Hash of the data to verify.
	 * @param signature
	 *            the signature
	 * @param Q
	 *            the public key point on the elliptic curve
	 * @return {@code true} if the signature has been verified
	 */
	public static boolean verifySignature(@NonNull final byte[] hash,
			@NonNull final ECDSASignature signature, @NonNull final ECPoint Q) {

		// 0. Check Q is not identity and is on the curve
		// If not, the public key is invalid.
		if (Q.isInfinity()) {
			return false;
		}
		if (!Q.multiply(N).isInfinity()) {
			return false;
		}

		// 1. Verify that r and s are integers in the interval [1,n-1].
		// If not, the signature is invalid.
		if (!signature.isValid()) {
			return false;
		}

		// 2. Calculate e = HASH(message)
		// 3. and Let z be the n.bitLength() leftmost bits of e.
		final BigInteger z = calculateZ(hash);

		// 4. Calculate w = s^-1
		final BigInteger w = signature.getS().modInverse(N);

		// 5. Calculate u1 = z.w and u2 = r.w
		final BigInteger u1 = z.multiply(w).mod(N);
		final BigInteger u2 = signature.getR().multiply(w).mod(N);

		// 6. Calculate the curve point u1 * G + u2 * Q
		final ECPoint point = sumOfTwoMultiplies(G, u1, Q, u2);

		// 7. The signature is valid if r=point.x, invalid otherwise.
		final ECFieldElement coorX = point.getX();
		if (coorX == null) {
			return false; // Got infinity !?
		}
		final BigInteger v = coorX.toBigInteger().mod(N);

		return signature.getR().equals(v);
	}

	/**
	 * Given the components of a signature, recover and return the public key
	 * that generated the signature according to the algorithm in SEC1v2 section
	 * 4.1.6.
	 * <p>
	 * The keyIdx is an index from 0 to 3 which indicates which of the 4
	 * possible keys is needed. Because the key recovery operation yields
	 * multiple potential keys, the correct key must either be stored alongside
	 * the signature, or you must be willing to try each keyIdx in turn until
	 * you find one that outputs the key you are expecting.
	 * <p>
	 * If this method returns null it means recovery was not possible.
	 * 
	 * @param hash
	 *            Hash of the data to verify.
	 * @param signature
	 *            the signature.
	 * @param keyIdx
	 *            Which possible key to recover.
	 * 
	 * @return {@code null} or a candidate public key
	 * @throws IllegalArgumentException
	 */
	@Nullable
	public static ECPoint recoverFromSignature(@NonNull final byte[] hash,
			@NonNull final ECDSASignature signature, final int keyIdx) {
		if (keyIdx < 0 || keyIdx > 3) {
			throw new IllegalArgumentException("Invalid key index"); //$NON-NLS-1$
		}

		// 0. Verify that r and s are integers in the interval [1,n-1].
		// If not, the signature is invalid.
		if (!signature.isValid()) {
			throw new IllegalArgumentException("Signature r value out of range"); //$NON-NLS-1$
		}

		// 1. Let x = r + jn
		final BigInteger j = BigInteger.valueOf((long) keyIdx / 2);
		final BigInteger x = signature.getR().add(j.multiply(N));
		if (x.compareTo(P) >= 0) {
			// Cannot have point co-ordinates larger than this as everything
			// takes place modulo p.
			return null;
		}

		// 2. Consider x as the x coordinate of a point on the curve
		ECPoint R;
		try {
			R = new ECPoint(x, (keyIdx & 1) == 0);
		} catch (final IllegalArgumentException e) {
			return null;
		}

		// 3. If nR != point at infinity, then ???
		if (!R.multiply(N).isInfinity()) {
			return null;
		}

		// 4. Calculate e = HASH(message)
		// .. and Let z be the n.bitLength() leftmost bits of e.
		final BigInteger z = calculateZ(hash);

		// 5. N/A
		// 6. Compute a candidate public key as: Q = r^-1 (sR - eG)
		//
		// We transform this into the following:
		// Q = (r^-1 * s ** R) + (s^-1 * -e ** G)
		// Where -e is the modular additive inverse of e, that is z such that z
		// + e = 0 (mod n). In the above equation ** is point multiplication and
		// + is point addition (the EC group operator).
		//
		// We can find the additive inverse by subtracting e from zero then
		// taking the mod. For example the additive inverse of 3 modulo 11 is 8
		// because 3 + 8 mod 11 = 0, and -3 mod 11 = 8.
		final BigInteger eInv = BigInteger.ZERO.subtract(z).mod(N);
		final BigInteger rInv = signature.getR().modInverse(N);
		final BigInteger srInv = rInv.multiply(signature.getS()).mod(N);
		final BigInteger eInvrInv = rInv.multiply(eInv).mod(N);
		final ECPoint p1 = G.multiply(eInvrInv);
		final ECPoint p2 = R.multiply(srInv);

		return p2.add(p1);
	}

	/**
	 * Given the components of a signature, recover and return the public key
	 * that generated the signature according to the algorithm in SEC1v2 section
	 * 4.1.6.
	 * <p>
	 * Out of the 4 possible public keys, the public key returned is the one
	 * that generate the given address. Notice that, as we don't know if the
	 * address has been generated using a compressed or uncompressed key, we
	 * must try both! If this method returns null it means recovery was not
	 * possible.
	 * 
	 * @param hash
	 *            Hash of the data to verify.
	 * @param signature
	 *            the signature.
	 * @param address
	 *            address to be used to validate the public key. We don't know
	 *            Whether this address use compressed or uncompressed form!
	 * @return {@code null} or a candidate public key
	 */
	@Nullable
	public static ECPoint recoverFromSignature(@NonNull final byte[] hash,
			@NonNull final ECDSASignature signature,
			final BitcoinAddress address) {

		// 0. Verify that r and s are integers in the interval [1,n-1].
		// If not, the signature is invalid.
		if (!signature.isValid()) {
			return null;
		}

		// 4. Calculate e = HASH(message)
		// .. and Let z be the n.bitLength() leftmost bits of e.
		final BigInteger z = calculateZ(hash);

		for (int j = 0; j <= 1; j++) {
			// 1. Let x = r + jn mod p ???
			BigInteger x = signature.getR();
			if (j != 0) {
				x = x.add(N);
			}

			if (x.compareTo(P) >= 0) {
				// Cannot have point co-ordinates larger than this as everything
				// takes place modulo p.
				continue;
			}

			// 2. Consider x as the x coordinate of a point on the curve
			// There is two solutions (y>0 and y<0). Take any one!
			ECPoint R;
			try {
				R = new ECPoint(x, true);
			} catch (final IllegalArgumentException e) {
				continue;
			}

			// 3. If nR != point at infinity, then do another iteration of step
			// of j
			if (!R.multiply(N).isInfinity()) {
				continue;
			}

			// 5. For k from 1 to 2 do the following.
			for (int k = 1; k <= 2; k++) {
				// 6. Compute a candidate public key as: Q = r^-1 (sR - eG)
				//
				// We transform this into the following:
				// Q = (r^-1 * s ** R) + (s^-1 * -e ** G) Where -e is the
				// modular additive inverse of e, that is z such that z + e = 0
				// (mod n).
				// In the above equation ** is point multiplication and + is
				// point addition (the EC group operator).
				//
				// We can find the additive inverse by subtracting e from zero
				// then taking the mod. For example the additive inverse of 3
				// modulo 11 is 8 because 3 + 8 mod 11 = 0, and -3 mod 11 = 8.
				final BigInteger eInv = BigInteger.ZERO.subtract(z).mod(N);
				final BigInteger rInv = signature.getR().modInverse(N);
				final BigInteger srInv = rInv.multiply(signature.getS()).mod(N);
				final BigInteger eInvrInv = rInv.multiply(eInv).mod(N);
				final ECPoint p1 = G.multiply(eInvrInv);
				final ECPoint p2 = R.multiply(srInv);

				final ECPoint Q = p2.add(p1);

				// 7. Check that Q is the signing public key
				// Nota: we cannot use verifySignature(hash, r, s, Q) because
				// ALL 4 possible keys will validate. We must use the point to
				// generate an adress and compare with the provided address!

				// try compressed first as this is the standard
				BitcoinAddress addr = new BitcoinAddress(
						address.isProduction(), Q, true);
				if (addr.equals(address)) {
					return Q;
				}
				// try uncompressed
				addr = new BitcoinAddress(address.isProduction(), Q, false);
				if (addr.equals(address)) {
					return Q;
				}

				// 8. set R=-R
				R = R.negate();
			}
		}
		return null;
	}

	@NonNull
	private static BigInteger calculateZ(@NonNull final byte[] message) {
		final int messageBitLength = message.length * 8;

		BigInteger z = new BigInteger(1, message);

		if (256 < messageBitLength) {
			z = z.shiftRight(messageBitLength - 256);
		}

		return z;
	}

	/**
	 * Shamir's trick to Compute k*P + l*Q
	 */
	// TODO tester vitesse par rapport au calcul direct!
	@NonNull
	private static ECPoint sumOfTwoMultiplies(@NonNull final ECPoint ptP,
			@NonNull final BigInteger k, @NonNull final ECPoint ptQ,
			@NonNull final BigInteger l) {

		final int m = Math.max(k.bitLength(), l.bitLength());
		final ECPoint z = ptP.add(ptQ);
		ECPoint r = O;

		for (int i = m - 1; i >= 0; --i) {
			r = r.twice();

			if (k.testBit(i)) {
				if (l.testBit(i)) {
					r = r.add(z);
				} else {
					r = r.add(ptP);
				}
			} else {
				if (l.testBit(i)) {
					r = r.add(ptQ);
				}
			}
		}

		return r;
	}
}

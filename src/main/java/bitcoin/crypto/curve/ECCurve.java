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
import java.security.SecureRandom;
import java.util.Random;

import jsr305.NonNull;

/**
 * Static class representing the EC used in bitcoin (secp256k1)
 * <p>
 * secp256k1 refers to the parameters of the ECDSA curve used in Bitcoin, and is
 * defined in Standards for Efficient Cryptography (SEC) (Certicom Research,
 * http://www.secg.org/collateral/sec2_final.pdf). As excerpted from Standards:
 * <p>
 * The elliptic curve domain parameters over {@code Fp} associated with a
 * Koblitz curve secp256k1 are specified by the sextuple
 * {@code (p, a, b, G, n, h)} where the finite field {@code Fp} is defined by:
 * 
 * <pre>
 * p = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F 
 * p = 2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1
 * </pre>
 * 
 * The curve {@code E: y^2 = x^3 + ax + b} over {@code Fp} is defined by:
 * 
 * <pre>
 * a = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000000 
 * b = 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00000007
 * </pre>
 * 
 * The base point {@code G} in compressed form is:
 * 
 * <pre>
 * G = 02 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798
 * </pre>
 * 
 * and in uncompressed form is:
 * 
 * <pre>
 * G = 04 79BE667E F9DCBBAC 55A06295 CE870B07 029BFCDB 2DCE28D9 59F2815B 16F81798 483ADA77 26A3C465 5DA4FBFC 0E1108A8 FD17B448 A6855419 9C47D08F FB10D4B8
 * </pre>
 * 
 * Finally the order {@code n} of {@code G} and the cofactor are:
 * 
 * <pre>
 * n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141 
 * h = 01
 * </pre>
 */
public interface ECCurve {

	/**
	 * Random generator
	 */
	Random SECURE_RANDOM = new SecureRandom();

	/**
	 * Field characteristic
	 * {@code  2^256 - 2^32 - 2^9 - 2^8 - 2^7 - 2^6 - 2^4 - 1}
	 */
	@NonNull
	BigInteger P = new BigInteger(
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16); //$NON-NLS-1$;

	/**
	 * EC Curve parameter {@code y^2 = x^3 + 7}
	 * <p>
	 * a=0, b=7
	 */
	@NonNull
	ECFieldElement B = new ECFieldElement(BigInteger.valueOf(7));

	/**
	 * base point {@code G}
	 */
	@NonNull
	ECFieldElement GX = new ECFieldElement(new BigInteger(
			"79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", //$NON-NLS-1$
			16));
	@NonNull
	ECFieldElement GY = new ECFieldElement(new BigInteger(
			"483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", //$NON-NLS-1$
			16));
	@NonNull
	ECPoint G = new ECPoint(GX, GY);

	/**
	 * order {@code n} of {@code G}
	 */
	@NonNull
	BigInteger N = new BigInteger(
			"FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16); //$NON-NLS-1$

	/**
	 * cofactor
	 */
	@NonNull
	BigInteger H = BigInteger.valueOf(1);

	/**
	 * Point at infinity
	 */
	@NonNull
	ECPoint O = new ECPoint();

	/**
	 * Number of bits of p or n
	 */
	int FIELD_SIZE = 256;

}

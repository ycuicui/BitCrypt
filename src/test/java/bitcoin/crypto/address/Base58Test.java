/**
 * This work is released under the BSD Licence
 * 
 * Copyright (c) 2013, Yves Cuillerdier 
 * All rights reserved.
 * 
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 
 *   o Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer. 
 *   o Redistributions in binary form must reproduce the above copyright notice, 
 *     this list of conditions and the following disclaimer in the documentation 
 *     and/or other materials provided with the distribution. 
 *   o Neither the name Yves Cuillerdier nor the names of its contributors may 
 *     be used to endorse or promote products derived from this software without 
 *     specific prior written permission.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER
 * OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
 * PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
package bitcoin.crypto.address;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.math.BigInteger;
import java.util.Arrays;

import junit.framework.Assert;

import org.junit.Test;

/**
 * 
 * @author Yves Cuillerdier <yves@cuillerdier.net>
 */
@SuppressWarnings({ "nls", "static-method" })
public class Base58Test {

	@Test
	public void testEncode() {
		final byte[] testbytes = "Hello World".getBytes();
		assertEquals("JxF12TrwUP45BMd", Base58.encode(testbytes));

		final BigInteger bi = BigInteger.valueOf(3471844090L);
		assertEquals("16Ho7Hs", Base58.encode(bi.toByteArray()));

		final byte[] zeroBytes1 = new byte[1];
		assertEquals("1", Base58.encode(zeroBytes1));

		final byte[] zeroBytes7 = new byte[7];
		assertEquals("1111111", Base58.encode(zeroBytes7));
	}

	@Test
	public void testDecode() {
		final byte[] testbytes = "Hello World".getBytes();
		byte[] actualbytes;
		try {
			actualbytes = Base58.decode("JxF12TrwUP45BMd");
			assertTrue(new String(actualbytes),
					Arrays.equals(testbytes, actualbytes));
		} catch (final AddressFormatException e1) {
			Assert.fail();
		}

		try {
			assertTrue("1", Arrays.equals(Base58.decode("1"), new byte[1]));
		} catch (final AddressFormatException e1) {
			Assert.fail();
		}

		try {
			assertTrue("1111",
					Arrays.equals(Base58.decode("1111"), new byte[4]));
		} catch (final AddressFormatException e1) {
			Assert.fail();
		}

		try {
			Base58.decode("This isn't valid base58");
			fail();
		} catch (final AddressFormatException e) {
			// OK
		}
	}

}

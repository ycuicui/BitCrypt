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
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
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

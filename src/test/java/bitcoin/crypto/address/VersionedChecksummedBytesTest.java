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

import junit.framework.Assert;

import org.junit.Test;

/**
 * 
 * @author Yves Cuillerdier <ycuicui@cuillerdier.net>
 */
@SuppressWarnings({ "nls", "static-method", "unused" })
public class VersionedChecksummedBytesTest {

	@Test
	public void testDecode() {

		try {
			new VersionedChecksummedBytes("4stwEBjT6FYyVV");
		} catch (final AddressFormatException e) {
			Assert.fail();
		}

		// Now check we can correctly decode the case where the high bit of the
		// first byte is not zero, so BigInteger sign extends.
		try {
			new VersionedChecksummedBytes(
					"93VYUMzRG9DdbRP72uQXjaWibbQwygnvaCu9DumcqDjGybD864T");
		} catch (final AddressFormatException e) {
			Assert.fail();
		}
	}

}

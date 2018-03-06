/**
 * Copyright (c) Codice Foundation
 *
 * <p>This is free software: you can redistribute it and/or modify it under the terms of the GNU
 * Lesser General Public License as published by the Free Software Foundation, either version 3 of
 * the License, or any later version.
 *
 * <p>This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details. A copy of the GNU Lesser General Public
 * License is distributed along with this program and can be found at
 * <http://www.gnu.org/licenses/lgpl.html>.
 */
package org.codice.security.sign;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import org.junit.Test;

public class SystemCryptoTest {

  private static final String HOSTNAME = "localhost";
  private static final String PASS = "changeit";

  @Test
  public void testCreateSystemCrypto() throws IOException {
    SystemCrypto crypto = new SystemCrypto();

    assertThat(crypto.getEncryptionAlias(), is(HOSTNAME));
    assertThat(crypto.getEncryptionPassword(), is(PASS));
    assertThat(crypto.getEncryptionCrypto(), is(notNullValue()));

    assertThat(crypto.getSignatureAlias(), is(HOSTNAME));
    assertThat(crypto.getSignaturePassword(), is(PASS));
    assertThat(crypto.getSignatureCrypto(), is(notNullValue()));
  }
}

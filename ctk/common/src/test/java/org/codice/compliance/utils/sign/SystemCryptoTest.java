/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.utils.sign;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import java.io.IOException;
import org.junit.jupiter.api.Test;

public class SystemCryptoTest {

  private static final String HOSTNAME = "samlhost";
  private static final String PASS = "changeit";

  @Test
  public void testCreateSystemCrypto() throws IOException {
    SystemCrypto crypto = new SystemCrypto(HOSTNAME);

    assertThat(crypto.getEncryptionAlias(), is(HOSTNAME));
    assertThat(crypto.getEncryptionPassword(), is(PASS));
    assertThat(crypto.getEncryptionCrypto(), is(notNullValue()));

    assertThat(crypto.getSignatureAlias(), is(HOSTNAME));
    assertThat(crypto.getSignaturePassword(), is(PASS));
    assertThat(crypto.getSignatureCrypto(), is(notNullValue()));
  }
}

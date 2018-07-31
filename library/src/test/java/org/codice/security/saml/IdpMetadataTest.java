/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.security.saml;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;

import com.google.common.io.Files;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.junit.jupiter.api.Test;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

public class IdpMetadataTest {

  private static final String IDP_ENTITY_ID = "https://localhost:8993/services/idp/login";

  @Test
  public void testParseIdPMetadata() throws Exception {
    String metadataString =
        Files.asCharSource(
                new File(getClass().getClassLoader().getResource("ddf-idp-metadata.xml").toURI()),
                StandardCharsets.UTF_8)
            .read();

    IdpMetadata idpMetadata = new IdpMetadata();
    idpMetadata.setMetadata(metadataString);
    Map<String, EntityDescriptor> metadata = idpMetadata.parseMetadata();

    assertThat(metadata, is(notNullValue()));
    assertThat(metadata.size(), is(1));

    EntityDescriptor entityDescriptor = metadata.get(IDP_ENTITY_ID);
    assertThat(entityDescriptor, is(notNullValue()));
  }
}

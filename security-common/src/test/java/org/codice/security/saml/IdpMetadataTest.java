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
package org.codice.security.saml;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.junit.Assert.assertThat;

import java.util.Map;
import org.junit.Test;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;

public class IdpMetadataTest {

  private static final String IDP_ENTITY_ID = "https://localhost:8993/services/idp/login";

  @Test
  public void testParseSPMetadata() {
    String metadataPath = this.getClass().getClassLoader().getResource("ddf-idp-metadata.xml").getPath();

    IdpMetadata idpMetadata = new IdpMetadata();
    idpMetadata.setMetadata(metadataPath);
    Map<String, EntityDescriptor> metadata = idpMetadata.parseMetadata();

    assertThat(metadata, is(notNullValue()));
    assertThat(metadata.size(), is(1));

    EntityDescriptor entityDescriptor = metadata.get(IDP_ENTITY_ID);
    assertThat(entityDescriptor, is(notNullValue()));
  }
}

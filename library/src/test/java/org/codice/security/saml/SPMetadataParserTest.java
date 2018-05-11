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
import static org.hamcrest.MatcherAssert.assertThat;

import com.google.common.collect.ImmutableSet;
import com.google.common.io.Files;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import org.codice.security.saml.SamlProtocol.Binding;
import org.junit.jupiter.api.Test;

public class SPMetadataParserTest {

  private static final String SP_ENTITY_ID = "https://localhost:8993/services/saml";

  @Test
  public void testParseSPMetadata() throws Exception {
    String metadataString =
        Files.toString(
            new File(getClass().getClassLoader().getResource("test-sp-metadata.xml").toURI()),
            StandardCharsets.UTF_8);

    Map<String, EntityInformation> spMetadata =
        SPMetadataParser.parse(
            metadataString, ImmutableSet.of(Binding.HTTP_REDIRECT, Binding.HTTP_POST));

    assertThat(spMetadata, is(notNullValue()));
    assertThat(spMetadata.size(), is(1));

    EntityInformation entityInformation = spMetadata.get(SP_ENTITY_ID);
    assertThat(entityInformation, is(notNullValue()));
  }
}

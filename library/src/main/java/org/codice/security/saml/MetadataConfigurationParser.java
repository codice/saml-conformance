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

import java.io.Reader;
import java.io.StringReader;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.function.Consumer;
import org.apache.cxf.staxutils.StaxUtils;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.metadata.EntitiesDescriptor;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

public class MetadataConfigurationParser {

  private static final Logger LOGGER = LoggerFactory.getLogger(MetadataConfigurationParser.class);
  private static final String ENTITIES_DESCRIPTOR = "EntitiesDescriptor";

  static {
    OpenSAMLUtil.initSamlEngine();
  }

  private final Map<String, EntityDescriptor> entityDescriptorMap = new ConcurrentHashMap<>();
  private final Consumer<EntityDescriptor> updateCallback;

  public MetadataConfigurationParser(String entityDescriptions) {
    this(entityDescriptions, null);
  }

  public MetadataConfigurationParser(
      String metadataString, Consumer<EntityDescriptor> updateCallback) {
    this.updateCallback = updateCallback;
    buildEntityDescriptors(metadataString);
  }

  public Map<String, EntityDescriptor> getEntryDescriptions() {
    return entityDescriptorMap;
  }

  /**
   * Parses and builds an entity descriptor for metadatas.
   *
   * @param metadataString - metadata
   */
  private void buildEntityDescriptors(String metadataString) {
    if (metadataString.startsWith("<") && metadataString.endsWith(">")) {
      XMLObject xmlObject = readMetadata(new StringReader(metadataString.trim()));

      if (metadataString.contains(ENTITIES_DESCRIPTOR)) {
        EntitiesDescriptor entitiesDescriptor = (EntitiesDescriptor) xmlObject;
        entitiesDescriptor.getEntityDescriptors().forEach(this::processEntityDescriptor);
      } else {
        processEntityDescriptor((EntityDescriptor) xmlObject);
      }
    }
  }

  private XMLObject readMetadata(Reader reader) {
    Document entityDoc;
    try {
      entityDoc = StaxUtils.read(reader);
    } catch (Exception ex) {
      throw new IllegalArgumentException("Unable to read SAMLRequest as XML.", ex);
    }
    try {
      return OpenSAMLUtil.fromDom(entityDoc.getDocumentElement());
    } catch (WSSecurityException ex) {
      throw new IllegalArgumentException(
          "Unable to convert EntityDescriptor document to XMLObject.", ex);
    }
  }

  private void processEntityDescriptor(EntityDescriptor entityDescriptor) {
    if (entityDescriptor.getCacheDuration() == null && entityDescriptor.getValidUntil() == null) {
      LOGGER.trace(
          "IDP metadata must either have cache duration or valid-until date."
              + " Defaulting IDP metadata cache duration to {}",
          SamlProtocol.getCacheDuration());
      entityDescriptor.setCacheDuration(SamlProtocol.getCacheDuration().toMillis());
    }

    entityDescriptorMap.put(entityDescriptor.getEntityID(), entityDescriptor);
    if (updateCallback != null) {
      updateCallback.accept(entityDescriptor);
    }
  }
}

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
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;

public class MetadataConfigurationParser {

  private static final Logger LOGGER = LoggerFactory.getLogger(MetadataConfigurationParser.class);

  static {
    OpenSAMLUtil.initSamlEngine();
  }

  private final Map<String, EntityDescriptor> entityDescriptorMap = new ConcurrentHashMap<>();
  private final Consumer<EntityDescriptor> updateCallback;

  public MetadataConfigurationParser(String entityDescriptions) {
    this(entityDescriptions, null);
  }

  public MetadataConfigurationParser(
      String entityDescriptions, Consumer<EntityDescriptor> updateCallback) {
    this.updateCallback = updateCallback;
    buildEntityDescriptor(entityDescriptions);
  }

  public Map<String, EntityDescriptor> getEntryDescriptions() {
    return entityDescriptorMap;
  }

  /**
   * Parses and builds an entity descriptor for metadatas.
   *
   * @param entityDescription - metadata
   */
  private void buildEntityDescriptor(String entityDescription) {
    EntityDescriptor entityDescriptor = null;
    entityDescription = entityDescription.trim();

    if (entityDescription.startsWith("<") && entityDescription.endsWith(">")) {
      entityDescriptor = readEntityDescriptor(new StringReader(entityDescription));
    }

    if (entityDescriptor != null) {
      entityDescriptorMap.put(entityDescriptor.getEntityID(), entityDescriptor);
      if (updateCallback != null) {
        updateCallback.accept(entityDescriptor);
      }
    }
  }

  private EntityDescriptor readEntityDescriptor(Reader reader) {
    Document entityDoc;
    try {
      entityDoc = StaxUtils.read(reader);
    } catch (Exception ex) {
      throw new IllegalArgumentException("Unable to read SAMLRequest as XML.");
    }
    XMLObject entityXmlObj;
    try {
      entityXmlObj = OpenSAMLUtil.fromDom(entityDoc.getDocumentElement());
    } catch (WSSecurityException ex) {
      throw new IllegalArgumentException(
          "Unable to convert EntityDescriptor document to XMLObject.");
    }
    EntityDescriptor root = (EntityDescriptor) entityXmlObj;
    validateMetadata(root);
    return root;
  }

  private void validateMetadata(EntityDescriptor root) {
    if (root.getCacheDuration() == null && root.getValidUntil() == null) {
      LOGGER.trace(
          "IDP metadata must either have cache duration or valid-until date."
              + " Defaulting IDP metadata cache duration to {}",
          SamlProtocol.getCacheDuration());
      root.setCacheDuration(SamlProtocol.getCacheDuration().toMillis());
    }
  }
}

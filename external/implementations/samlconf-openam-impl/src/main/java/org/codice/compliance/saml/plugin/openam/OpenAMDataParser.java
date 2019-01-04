/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.saml.plugin.openam;

import com.google.common.collect.ImmutableMap;
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.codice.compliance.utils.TestCommon;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/**
 * OpenAMDataParser:
 *
 * Retrieves the configurable files from the OpenAMLoginData xml file
 **/
class OpenAMDataParser {

  private final ImmutableMap<String, String> formMapping;
  private final String openAMRealm;
  private final String baseURL;

  private static final String REALM = "realmName";
  private static final String BASE_URL = "baseUrl";
  private static final String LOGIN_FORM = "loginForm";
  private static final String INPUT = "input-";
  private static final String OUTPUT = "output-";

  private static final String USER_ARG = "USER.ARG";
  private static final String PASSWORD_ARG = "PASS.ARG";

  private static final String fileName = "OpenAMLoginData.xml";

  /**
   * OpenAMDataParser:
   *
   * @throws IllegalStateException when the OpenAMLoginData file cannot be found or accessed.
   */
  OpenAMDataParser() {

    DocumentBuilder doc;
    try {
      DocumentBuilderFactory docBF = DocumentBuilderFactory.newInstance();
      doc = docBF.newDocumentBuilder();
    } catch (ParserConfigurationException e) {
      throw new IllegalStateException(e);
    }

    Document xml;
    try {
      xml = doc.parse(new File(TestCommon.Companion.getImplementationPath(), fileName));
    } catch (IOException | SAXException e) {
      throw new IllegalStateException(e);
    }

    //  Parsing the XML login data
    String tempRealm = xml.getElementsByTagName(REALM).item(0).getTextContent();
    openAMRealm = (tempRealm.equals("/")) ? "" : tempRealm;
    baseURL = xml.getElementsByTagName(BASE_URL).item(0).getTextContent();

    //  Since the authentication payload sent is customizable by the client of OpenAM
    //  This parsing has to be dynamic. Loop through the login form tag and continue while
    //  both the Input and Output tags are supplied.
    Element loginInfo = (Element) xml.getElementsByTagName(LOGIN_FORM).item(0);

    Map<String, String> tempMap = new HashMap<>();
    int i = 1;
    while (hasChildTag(loginInfo, INPUT + i) && hasChildTag(loginInfo, OUTPUT + i)) {

      tempMap.put(
          loginInfo.getElementsByTagName(INPUT + i).item(0).getTextContent(),
          expandArg(loginInfo.getElementsByTagName(OUTPUT + i).item(0).getTextContent()));
      i++;
    }

    formMapping = ImmutableMap.copyOf(tempMap);
  }

  private boolean hasChildTag(Element element, String tagName) {
    return element.getElementsByTagName(tagName).getLength() != 0;
  }

  private String expandArg(String arg) {
    //  Check to see if it's an argument to expand and expand it.
    switch (arg) {
      case USER_ARG:
        return TestCommon.Companion.getUsername();
      case PASSWORD_ARG:
        return TestCommon.Companion.getPassword();
      default:
        return arg;
    }
  }

  ImmutableMap<String, String> getFormMapping() {
    return formMapping;
  }

  String getOpenAMRealm() {
    return openAMRealm;
  }

  String getRealmsUrl() {
    return (openAMRealm.isEmpty()) ? "" : "/realms";
  }

  String getBaseURL() {
    return baseURL;
  }
}

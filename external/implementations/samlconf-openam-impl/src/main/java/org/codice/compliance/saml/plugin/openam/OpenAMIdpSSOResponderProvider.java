/*
Copyright (c) 2018 Codice Foundation

Released under the GNU Lesser General Public License; see
http://www.gnu.org/licenses/lgpl.html
*/
package org.codice.compliance.saml.plugin.openam;

import com.google.common.base.Splitter;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import java.io.UnsupportedEncodingException;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import org.codice.compliance.saml.plugin.IdpSSOResponder;
import org.codice.compliance.utils.ConstantsKt;
import org.codice.compliance.utils.GlobalSession;
import org.kohsuke.MetaInfServices;

/**
 * OpenAMIdpSSOResponderProvider:
 *
 * Handles authenticating the user to the OpenAM IdP
 */
@MetaInfServices
public class OpenAMIdpSSOResponderProvider implements IdpSSOResponder {

  private static String TOKEN_ID = "tokenId";
  private static String CALLBACKS = "callbacks";
  private static OpenAMDataParser OPEN_AM_DATA = new OpenAMDataParser();

  private static String AUTH_URL =
      OPEN_AM_DATA.getBaseURL()
          + "/json/realms/root"
          + OPEN_AM_DATA.getRealmsUrl()
          + OPEN_AM_DATA.getOpenAMRealm()
          + "/authenticate";

  /**
   * getResponseForRedirectRequest:
   *
   * Handles the redirect request to the OpenAM IdP to authenticate the user.
   *
   * @throws SecurityException when the username and password can not authenticate the user.
   */
  @Override
  public Response getResponseForRedirectRequest(Response originalResponse) {
    return openAMLogin(originalResponse);
  }

  /**
   * getResponseForPostRequest:
   *
   * Handles the POST request to the OpenAM IdP to authenticate the user.
   *
   * @throws SecurityException when the username and password can not authenticate the user.
   */
  @Override
  public Response getResponseForPostRequest(Response originalResponse) {
    return openAMLogin(originalResponse);
  }

  private Response openAMLogin(Response res) {

    Map<String, String> queryParams = getQueryParams(res.getHeader(ConstantsKt.LOCATION));

    // -- Get the initial json form to fill in --
    JsonParser parser = new JsonParser();
    Response payloadRes = RestAssured.given().queryParams(queryParams).when().post(AUTH_URL);

    JsonObject payload = parser.parse(payloadRes.jsonPath().prettify()).getAsJsonObject();

    //  OpenAm will walk through the login chain until it passes the authentication check.
    do {
      JsonArray cbArr = payload.get(CALLBACKS).getAsJsonArray();

      cbArr.forEach(this::completeForm);

      // -- send the completed form to get authenticated --
      Response authRes =
          RestAssured.given()
              .when()
              .body(payload)
              .contentType("application/json")
              .log()
              .ifValidationFails()
              .queryParams(queryParams)
              .when()
              .post(AUTH_URL);

      payload = parser.parse(authRes.jsonPath().prettify()).getAsJsonObject();

    } while (payload.has(CALLBACKS));

    //  At this point payload either has a 401 or a token ID.
    if (!payload.has(TOKEN_ID)) {
      throw new SecurityException(
          "Failed login due to invalid credentials. "
              + "Check the SamlCTK OpenAM documentation for more information. "
              + OPEN_AM_DATA.getFormMapping().toString());
    }

    Map<String, String> cookies = new HashMap<>();
    cookies.put("iPlanetDirectoryPro", payload.get(TOKEN_ID).getAsString());

    //  iPlanetDirectoryPro is OpenAM's login cookie. If it's lost it will log off.
    GlobalSession.INSTANCE.addCookies(cookies);

    //  This get call returns a form with a button that is automatically clicked when the page is
    // rendered.
    String samlURL = queryParams.get("goto");

    //  Send the SAMLResponse to the original location header
    return RestAssured.given()
        .cookies(GlobalSession.INSTANCE.getCookies())
        .queryParams(queryParams)
        .urlEncodingEnabled(false)
        .redirects()
        .follow(true)
        .when()
        .get(samlURL);
  }

  private Map<String, String> getQueryParams(String locationHeader) {

    //  Decode the location header.
    String decodedLocation = locationHeader;
    Map<String, String> queryParamsMap = new HashMap<>();

    try {
      decodedLocation = URLDecoder.decode(locationHeader, StandardCharsets.UTF_8.name());
    } catch (UnsupportedEncodingException ignored) {
      //  error is ignored because it should never happen.
    }

    //  just incase there are oddities with multiple urls in the url
    Iterator<String> queryIter = Splitter.on("?").split(decodedLocation).iterator();

    //  Since we're splitting on "?" the first element will not be a query string.
    //  and we'll discard it.
    queryIter.next();

    while (queryIter.hasNext()) {

      Iterable<String> queryParams = Splitter.on("&").split(queryIter.next());

      for (String param : queryParams) {

        Iterable<String> temp = Splitter.on("=").split(param);
        Iterator<String> iter = temp.iterator();
        String name = iter.next();
        String val = (iter.hasNext()) ? iter.next() : "";
        queryParamsMap.put(name, val);
      }
    }
    return queryParamsMap;
  }

  /*
   * Parses through the json callback form and looks for elements
   * from the openAMLoginData. If it finds a match in the prompts, it will fill
   * out the corresponding value pair.
   */
  private void completeForm(JsonElement node) {
    String prompt =
        node.getAsJsonObject()
            .get("output")
            .getAsJsonArray()
            .get(0)
            .getAsJsonObject()
            .get("value")
            .getAsString();

    if (OPEN_AM_DATA.getFormMapping().containsKey(prompt)) {
      JsonObject element =
          node.getAsJsonObject().get("input").getAsJsonArray().get(0).getAsJsonObject();

      element.remove("value");
      element.addProperty("value", OPEN_AM_DATA.getFormMapping().get(prompt));
    }
  }
}

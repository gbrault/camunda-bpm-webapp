package org.camunda.bpm.webapp.impl.security.auth;

import java.io.IOException;
import java.security.Principal;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Context;
import javax.ws.rs.ext.Providers;

import org.camunda.bpm.engine.rest.util.ProvidersUtil;
import org.camunda.bpm.webapp.impl.security.provider.UserAuthentications;

/**
 * This Servlet filter relies on the Servlet container (application server) to
 * authenticate a user and only forward a request to the application upon
 * successful authentication.
 * 
 * It passes the username provided by the container through the Servlet API into
 * the Servlet session used by the Camunda REST API.
 *
 * The implementation is largely based on code from {@link AuthenticationFilter}
 * and {@link UserAuthenticationResource}.
 *
 * @author Eberhard Heber
 * @author Falko Menge
 */
public class ContainerManagedUserAuthenticationFilter implements Filter {

  @Context
  protected Providers providers;
  
  protected UserAuthentications userAuthentications;
  
  protected static final String APP_MARK = "/app/";

  public void init(FilterConfig filterConfig) throws ServletException {
    userAuthentications = ProvidersUtil.resolveFromContext(providers, UserAuthentications.class);
  }

  public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
    
    final HttpServletRequest req = (HttpServletRequest) request;

    // get authentication from session
    Authentications authentications = Authentications.getFromSession(req.getSession());
    Authentications.setCurrent(authentications);

    setKnownPrinicipal(req);

  }

  public void destroy() {
  }

  protected void setKnownPrinicipal(HttpServletRequest request) {
    String username = getUserName(request);
    if (username != null && !username.isEmpty()) {

      String engineName = getEngineName(request);
      if (!isAuthenticated(engineName, username)) {
        authenticate(username, engineName);
      }

    }
  }
  
  protected boolean isAuthenticated(String engineName, String username) {
    List<Authentication> authentications = getAuthentications();
    for (Authentication auth : authentications) {

      String authEngineName = auth.getProcessEngineName();
      String authUsername = auth.getName();

      if (engineName.equals(authEngineName) && username.equals(authUsername)) {
        return true;
      }

    }

    return false;
  }

  protected List<Authentication> getAuthentications() {
    Authentications auth = Authentications.getCurrent();
    return auth.getAuthentications();
  }

  protected void authenticate(String username, String engineName) {
    userAuthentications.authenticate(engineName, username);
  }

  protected String getUserName(HttpServletRequest request) {
    Principal principal = request.getUserPrincipal();
    return principal != null ? principal.getName() : null;
  }

  protected String getEngineName(HttpServletRequest request) {
    String url = request.getRequestURL().toString();
    String[] appInfo = getAppInfo(url);
    return getEngineName(appInfo);
  }

  protected String getEngineName(String[] appInfo) {
      if (appInfo != null && appInfo.length >= 2) {
        return appInfo[1];
      } else {
        return "default";
      }
  }

  /**
   * Retrieve app name and engine name from URL,
   * e.g. http://localhost:8080/camunda/app/tasklist/default/
   * 
   * TODO detect engine name for API calls,
   * e.g. http://localhost:8080/camunda/api/engine/engine/default/process-definition
   * or http://localhost:8080/camunda/api/cockpit/plugin/base/default/process-definition/invoice:2:b613aca2-71ed-11e7-8f37-0242d5fdf76e/called-process-definitions
   * 
   * Currently, API requests will always be authorized using the
   * process engine named "default". 
   */
  protected String[] getAppInfo(String url) {
      String[] appInfo = null;
      int index = url.indexOf(APP_MARK);
      if (index >= 0) {
        try {
          String apps = url.substring(index + APP_MARK.length(), url.length() - 1);
          String[] aa = apps.split("/");
          if (aa.length >= 1) {
            if (url.endsWith("/")) {
              appInfo = aa;
            } else {
              appInfo = new String[]{aa[0]};
            }
          }
        } catch (StringIndexOutOfBoundsException e) {
          
        }
      }
      return appInfo;
  }
}
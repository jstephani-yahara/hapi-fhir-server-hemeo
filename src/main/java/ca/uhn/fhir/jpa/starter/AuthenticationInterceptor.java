package ca.uhn.fhir.jpa.starter;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.codehaus.jettison.json.JSONObject;

import ca.uhn.fhir.i18n.Msg;
import ca.uhn.fhir.interceptor.api.Hook;
import ca.uhn.fhir.interceptor.api.Interceptor;
import ca.uhn.fhir.interceptor.api.Pointcut;
import ca.uhn.fhir.rest.api.server.RequestDetails;
import ca.uhn.fhir.rest.server.exceptions.AuthenticationException;
import ca.uhn.fhir.rest.server.interceptor.InterceptorAdapter;

@Interceptor
public class AuthenticationInterceptor extends InterceptorAdapter {
    @Hook(Pointcut.SERVER_INCOMING_REQUEST_POST_PROCESSED)
    public boolean incomingRequestPostProcessed(
      RequestDetails theRequestDetails, HttpServletRequest theRequest, HttpServletResponse theResponse)
      throws AuthenticationException {
        // Process this header
        String authHeader = theRequestDetails.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new AuthenticationException(Msg.code(642) + "Missing or invalid Authorization header");
        }

        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost request = new HttpPost(System.getenv("IAM_INTROSPECTION_ENDPOINT"));
            StringEntity requestEntity = new StringEntity("token=" + authHeader.split(" ")[1]);
            request.setHeader("Authorization", "Basic " + System.getenv("IAM_CLIENT_AUTH"));
            request.setHeader("Content-Type", "application/x-www-form-urlencoded");
            request.setEntity(requestEntity);

            HttpResponse response = httpClient.execute(request);
            String entity = EntityUtils.toString(response.getEntity());
            return response.getStatusLine().getStatusCode() == 200 && (new JSONObject(entity).get("active").toString().equals("true"));

        }
        catch (Exception e)
        {
            e.printStackTrace();
        }

        throw new AuthenticationException(Msg.code(401) + "Invalid credentials");
    }
}

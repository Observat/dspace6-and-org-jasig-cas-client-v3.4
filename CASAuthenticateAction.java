// dspace/dspace-xmlui/src/main/java/org/dspace/app/xmlui/aspect/eperson/CASAuthenticateAction.java
/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.app.xmlui.aspect.eperson;

import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletResponse;

import org.apache.avalon.framework.parameters.Parameters;
import org.apache.cocoon.acting.AbstractAction;
import org.apache.cocoon.environment.ObjectModelHelper;
import org.apache.cocoon.environment.Redirector;
import org.apache.cocoon.environment.Request;
import org.apache.cocoon.environment.SourceResolver;
import org.apache.cocoon.environment.http.HttpEnvironment;
import org.apache.cocoon.sitemap.PatternException;
import org.dspace.app.xmlui.utils.AuthenticationUtil;
import org.dspace.core.Context;
import org.dspace.eperson.EPerson;
import org.dspace.services.factory.DSpaceServicesFactory;

/*
 * @author Kaboré Wendin-Malegdé Patrick at Paris-Dauphine University
 * * @version $Revision: 1.0 $
 * @author Yuri Ablavatski, Sukhoi State Technical University of Gomel
 * CAS authentication has been adapted to DSpace 6
 * @version $Revision 1.3.20180103 $
 */

/**
 * Attempt to authenticate the user based upon their presented CAS credentials.
 * This action uses the http parameters as supplied by CAS server.
 * Read dspace.cfg for configuration detail.
 *
 * If the authentication attempt is successfull then an HTTP redirect will be
 * sent to the browser redirecting them to their original location in the
 * system before authenticated or if none is supplied back to the DSpace
 * homepage. The action will also return true, thus contents of the action will
 * be excuted.
 *
 * If the authentication attempt fails, the action returns false.
 *
 * Example use:
 *
 * <map:act name="Authenticate">
 *   <map:serialize type="xml"/>
 * </map:act>
 * <map:transform type="try-to-login-again-transformer">
 *
 * @author Scott Phillips
 */

public class CASAuthenticateAction extends AbstractAction
{

    /**
     * Attempt to authenticate the user.
     */
    public Map act(Redirector redirector, SourceResolver resolver, Map objectModel,
            String source, Parameters parameters) throws Exception
    {
        // First check if we are preforming a new login
        Request request = ObjectModelHelper.getRequest(objectModel);

        try
        {
            Context context = AuthenticationUtil.authenticate(objectModel, null,null, null);

            EPerson eperson = context.getCurrentUser();

            if (eperson != null)
            {
                // The user has successfully logged in
                String redirectURL = request.getContextPath();

                if (AuthenticationUtil.isInterupptedRequest(objectModel))
                {
                    // Resume the request and set the redirect target URL to
                    // that of the originaly interrupted request.
                    redirectURL += AuthenticationUtil.resumeInterruptedRequest(objectModel);
                }
                else
                {
                    // Otherwise direct the user to the login page
                    String loginRedirect = DSpaceServicesFactory.getInstance().getConfigurationService().getProperty("xmlui.user.loginredirect");
                    redirectURL += (loginRedirect != null) ? loginRedirect.trim() : "";
                }

                // Authentication successfull send a redirect.
                final HttpServletResponse httpResponse = (HttpServletResponse) objectModel.get(HttpEnvironment.HTTP_RESPONSE_OBJECT);

                httpResponse.sendRedirect(redirectURL);

                // log the user out for the rest of this current request, however they will be reauthenticated
                // fully when they come back from the redirect. This prevents caching problems where part of the
                // request is preformed fore the user was authenticated and the other half after it succedded. This
                // way the user is fully authenticated from the start of the request.
                context.setCurrentUser(null);

                return new HashMap();
            }
        }
        catch (SQLException sqle)
        {
            throw new PatternException("Unable to preform authentication",
                    sqle);
        }

        return null;
    }

}

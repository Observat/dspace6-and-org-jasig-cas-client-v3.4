// dspace/dspace-api/src/main/java/org/dspace/authenticate/CASAuthentication.java
/**
 * The contents of this file are subject to the license and copyright
 * detailed in the LICENSE and NOTICE files at the root of the source
 * tree and available online at
 *
 * http://www.dspace.org/license/
 */
package org.dspace.authenticate;

import java.io.IOException;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.collections.ListUtils;
import org.apache.log4j.Logger;
import org.dspace.authenticate.factory.AuthenticateServiceFactory;
import org.dspace.authenticate.service.AuthenticationService;
import org.dspace.authorize.AuthorizeException;
import org.dspace.core.Context;
import org.dspace.core.LogManager;
import org.dspace.eperson.EPerson;
import org.dspace.eperson.Group;
import org.dspace.eperson.factory.EPersonServiceFactory;
import org.dspace.eperson.service.EPersonService;
import org.dspace.services.ConfigurationService;
import org.dspace.services.factory.DSpaceServicesFactory;

import org.jasig.cas.client.validation.Cas20ServiceTicketValidator;
import org.jasig.cas.client.validation.Assertion;

/**
 * Authenticator for Central Authentication Service (CAS).
 *
 * @author Naveed Hashmi, University of Bristol
 * based on code developed by Nordija A/S (www.nordija.com) for Center of Knowledge Technology (www.cvt.dk)
 * @version $Revision: 1.0 $
 * @author Nicolás Kovac Neumann, Universidad de La Laguna
 * CAS authentication has been adapted to DSpace 3.1 (latest stable) and proved functionality with CAS 3.5.0
 * @version $Revision: 1.1 $
 * @author Tomasz Baria Boiński, Gdańsk University of Technology
 * CAS authentication has been adapted to DSpace 4.2 and integrated with SAML user query
 * @version $Revision 1.2 $
 * @author Yuri Ablavatski, Sukhoi State Technical University of Gomel
 * CAS authentication has been adapted to DSpace 6 and org.jasig.cas.client 3.4.1
 * @version $Revision 1.3.20180103 $
 */

public class CASAuthentication
    implements AuthenticationMethod {

    /** log4j category */
    private static Logger log = Logger.getLogger(CASAuthentication.class);

    protected AuthenticationService authenticationService = AuthenticateServiceFactory.getInstance().getAuthenticationService();
    protected ConfigurationService configurationService = DSpaceServicesFactory.getInstance().getConfigurationService();
    protected EPersonService ePersonService = EPersonServiceFactory.getInstance().getEPersonService();

    /**
     * Predicate, can new user automatically create EPerson.
     * Checks configuration value.  You'll probably want this to
     * be true to take advantage of a Web certificate infrastructure
     * with many more users than are already known by DSpace.
     */
    @Override
    public boolean canSelfRegister(Context context,
                                   HttpServletRequest request,
                                   String username)
        throws SQLException
    {
        return configurationService.getBooleanProperty("authentication-cas.webui.autoregister");
    }

    /**
     *  Nothing extra to initialize.
     */
    @Override
    public void initEPerson(Context context,
                            HttpServletRequest request,
                            EPerson eperson)
        throws SQLException
    {
    }

    /**
     * We don't use EPerson password so there is no reason to change it.
     */
    @Override
    public boolean allowSetPassword(Context context,
                                    HttpServletRequest request,
                                    String username)
        throws SQLException
    {
        return false;
    }

    /**
     * Predicate, is this an implicit authentication method.
     * An implicit method gets credentials from the environment (such as
     * an HTTP request or even Java system properties) rather than the
     * explicit username and password.  For example, a method that reads
     * the X.509 certificates in an HTTPS request is implicit.
     * @return true if this method uses implicit authentication.
     *
     * Returns true, CAS is an implicit method
     */
    @Override
    public boolean isImplicit()
    {
        return true;
    }

    /**
     * No special groups.
     */
    @Override
    public List<Group> getSpecialGroups(Context context, HttpServletRequest request)
    {
        return ListUtils.EMPTY_LIST;
    }


    /**
     * CAS authentication.
     *
     * @return One of:
     *   SUCCESS, BAD_CREDENTIALS, CERT_REQUIRED, NO_SUCH_USER, BAD_ARGS
     */
    @Override
    public int authenticate(Context context,
                            String username,
                            String password,
                            String realm,
                            HttpServletRequest request)
        throws SQLException
    {
        final String ticket = request.getParameter("ticket");
        final String service = request.getRequestURL().toString();

        if (ticket != null && ticket.startsWith("ST") )
        {
            try
            {
                // Determine CAS validation URL
                String casServerUrl = configurationService.getProperty("authentication-cas.server.url");
                if (casServerUrl == null)
                {
                    throw new ServletException("No CAS validation URL specified. You need to set property 'authentication-cas.server.url'");
                }

                // Validate ticket
                Assertion assertion = validate( service, ticket, casServerUrl );
                if (assertion == null)
                {
                    throw new ServletException("Ticket '" + ticket + "' is not valid");
                }
                String netid = assertion.getPrincipal().getName();

                Boolean debug = configurationService.getBooleanProperty("authentication-cas.debug.enable");
                String debug_prefix = null;
                if( debug ) {
                    debug_prefix = configurationService.getProperty("authentication-cas.debug.prefix");
                    netid = debug_prefix + netid;
                }

                // Locate the eperson in DSpace
                EPerson eperson = null;
                try
                {
                    eperson = ePersonService.findByNetid(context, netid.toLowerCase());
                }
                catch (SQLException e)
                {
                    log.error("cas findbynetid failed");
                    log.error(e.getStackTrace());
                }

                // if they entered a netd that matches an eperson and they are allowed to login
                if (eperson != null)
                {
                    // e-mail address corresponds to active account
                    if (eperson.getRequireCertificate())
                    {
                        // they must use a certificate
                        return CERT_REQUIRED;
                    }
                    else if (!eperson.canLogIn()) {
                        return BAD_ARGS;
                    }

                    loginWithCasAttr(context, request, eperson);
                    return SUCCESS;
                }

                // the user does not exist in DSpace so create an eperson
                else
                {
                    if (canSelfRegister(context, request, netid) )
                    {
                        eperson = registerNewNetidFromCAS( context, request, assertion, netid );

                        loginWithCasAttr(context, request, eperson);
                        return SUCCESS;
                    }
                    else
                    {
                        log.warn(LogManager.getHeader(context, "authenticate", netid + " type=netid_but_no_record, cannot auto-register"));
                        return NO_SUCH_USER;
                    }
                }

            } catch (Exception e)
            {
                log.error(e.getStackTrace()[0]);
                //throw new ServletException(e);
            }
        }
        return BAD_ARGS;
    }


    private Assertion validate(String service, String ticket, String casServerUrl)
        throws IOException, ServletException
    {
        Assertion assertion = null;

        Cas20ServiceTicketValidator stv = new Cas20ServiceTicketValidator( casServerUrl );

        try {
            // java.net.URLEncoder.encode(service)
            assertion = stv.validate( ticket, service );
        } catch (Exception e) {
            log.error("Unexpected exception caught in Cas20ServiceTicketValidator.validate( ticket, service );", e);
            throw new ServletException(e);
        }

        return assertion;
    }

    private void loginWithCasAttr(Context context, HttpServletRequest request, EPerson eperson )
    {
        HttpSession session = request.getSession(false);
        if (session!=null) {
          session.setAttribute("loginType", "CAS");
        }

        context.setCurrentUser(eperson);
        log.info(LogManager.getHeader(context, "authenticate", "type=CAS"));
    }

    private EPerson registerNewNetidFromCAS(Context context, HttpServletRequest request, Assertion assertion, String netid )
        throws SQLException, AuthorizeException
    {
        String firstName = (String) assertion.getPrincipal()
                                             .getAttributes()
                                             .get(configurationService.getProperty("authentication-cas.assertion.attributes.firstName"));
        String lastName = (String) assertion.getPrincipal()
                                            .getAttributes()
                                            .get(configurationService.getProperty("authentication-cas.assertion.attributes.lastName"));

        String email = null;
        Object emails = assertion.getPrincipal().getAttributes().get(configurationService.getProperty("authentication-cas.assertion.attributes.email"));
        if (emails instanceof ArrayList) {
            email = (String)((ArrayList)emails).get(0);
        } else {
            email = (String) emails;
            if (email.indexOf('[') == 0) {
              email = email.substring(1, email.indexOf(','));
            }
        }
        if (email == null) {
            email = netid;
        }

        // TEMPORARILY turn off authorisation
        // Register the new user automatically
        //context.setIgnoreAuthorization(true);
        context.turnOffAuthorisationSystem();

        Boolean debug = configurationService.getBooleanProperty("authentication-cas.debug.enable");
        String debug_prefix = null;
        if( debug ) {
            debug_prefix = configurationService.getProperty("authentication-cas.debug.prefix");
            email = debug_prefix+email;
            firstName = debug_prefix+firstName;
            lastName = debug_prefix+lastName;
        }

        EPerson eperson = ePersonService.create(context);
        eperson.setNetid(netid);
        eperson.setLanguage(context, configurationService.getProperty("default.locale"));
        eperson.setEmail(email);
        eperson.setFirstName(context, firstName);
        eperson.setLastName(context, lastName);
        eperson.setRequireCertificate(false);
        eperson.setSelfRegistered(false);

        eperson.setCanLogIn(true);

        authenticationService.initEPerson(context, request, eperson);

        ePersonService.update(context, eperson);

        context.commit();
        context.restoreAuthSystemState();

        return eperson;
    }

    /*
     * Returns URL to which to redirect to obtain credentials (either password
     * prompt or e.g. HTTPS port for client cert.); null means no redirect.
     *
     * @param context
     *  DSpace context, will be modified (ePerson set) upon success.
     *
     * @param request
     *  The HTTP request that started this operation, or null if not applicable.
     *
     * @param response
     *  The HTTP response from the servlet method.
     *
     * @return fully-qualified URL
     */
    @Override
    public String loginPageURL(Context context,
                            HttpServletRequest request,
                            HttpServletResponse response)
    {
        // TODO Use org.jasig.cas.client.util.CommonUtils.constructRedirectUrl() or org.jasig.cas.client.util.CommonUtils.constructServiceUrl()
        final String authServer = configurationService.getProperty("authentication-cas.server.login.url");

        StringBuffer url = new StringBuffer(authServer);
        url.append("?service=").append(request.getScheme()).append("://").append(request.getServerName());
        if(request.getServerPort()!=80)
            url.append(":").append(request.getServerPort());
        url.append(request.getContextPath()).append("/cas-login");

        // Redirect to CAS server
        return response.encodeRedirectURL(url.toString());
    }

    /*
     * Returns message key for title of the "login" page, to use
     * in a menu showing the choice of multiple login methods.
     *
     * @param context
     *  DSpace context, will be modified (ePerson set) upon success.
     *
     * @return Message key to look up in i18n message catalog.
     */
    @Override
    public String loginPageTitle(Context context)
    {
        return "org.dspace.eperson.CASAuthentication.title";
    }
}

package com.keybox.manage.util;


import com.keybox.common.util.AppConfig;
import com.keybox.manage.db.AuthDB;
import com.keybox.manage.db.UserDB;
import com.keybox.manage.model.Auth;
import com.keybox.manage.model.User;
import org.apache.commons.lang3.StringUtils;

import javax.naming.*;
import javax.naming.directory.*;
import java.sql.Connection;
import java.util.Hashtable;
import java.util.UUID;

public class LdapUtil {

    private static String LDAP_SERVER_URL = null;
    private static String LDAP_BASE_DN = null;
    private static String LDAP_SECURITY_AUTHENTICATION = null;
    private static Hashtable<String, String> env = new Hashtable<>();

    public static final boolean ldapEnabled = "true".equals(AppConfig.getProperty("enableLDAP"));


    static {
        if (ldapEnabled) {
            LDAP_SERVER_URL = AppConfig.getProperty("ldapURL");
            LDAP_BASE_DN = AppConfig.getProperty("ldapBaseDN").replaceAll("^\\,", "");
            LDAP_SECURITY_AUTHENTICATION = AppConfig.getProperty("ldapSecurityAuth");

            env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
            env.put(Context.PROVIDER_URL, LDAP_SERVER_URL + "/" + LDAP_BASE_DN);
            env.put(Context.REFERRAL, "follow");
            env.put(Context.SECURITY_AUTHENTICATION, LDAP_SECURITY_AUTHENTICATION);
        }
    }


    /**
     * login
     *
     * @param auth contains username and password
     * @return authenctiction token if success
     */
    public static String login(Auth auth) {

        String authToken = null;
        if (ldapEnabled && auth != null && StringUtils.isNotEmpty(auth.getUsername()) && StringUtils.isNotEmpty(auth.getPassword())) {

            DirContext ctx = null;
            Connection con = null;
            try {


                String uid = "uid=" + auth.getUsername();
                String dn = uid + "," + LDAP_BASE_DN;

                env.put(Context.SECURITY_PRINCIPAL, dn);
                env.put(Context.SECURITY_CREDENTIALS, auth.getPassword());

                ctx = new InitialDirContext(env); //will throw exception
                Attributes attrs = ctx.getAttributes(uid);


                if (attrs.get("givenName") != null
                        && attrs.get("givenName").get() != null
                        && attrs.get("sn") != null
                        && attrs.get("sn").get() != null) {

                    con = DBUtils.getConn();
                    User user = AuthDB.getUserByUID(con, auth.getUsername());

                    if (user == null) {
                        user = new User();

                        user.setFirstNm((String) attrs.get("givenName").get());
                        user.setLastNm((String) attrs.get("sn").get());
                        if (attrs.get("mail") != null) {
                            user.setEmail((String) attrs.get("mail").get());
                        }

                        user.setUserType(User.ADMINISTRATOR);
                        user.setUsername(auth.getUsername());

                        user.setId(UserDB.insertUser(con, user));
                    }

                    authToken = UUID.randomUUID().toString();
                    user.setAuthToken(authToken);
                    user.setAuthType(Auth.AUTH_LDAP);
                    //set auth token
                    AuthDB.updateLogin(con, user);
                }

            } catch (AuthenticationException ex) { //login failed
                authToken = null;
            } catch (NamingException ex) {
                ex.printStackTrace();
            } finally {
                DBUtils.closeConn(con);

                if (ctx != null) {
                    try {
                        ctx.close();
                    } catch (Exception e) { /* ignore */ }
                }
            }
        }
        return authToken;
    }
}

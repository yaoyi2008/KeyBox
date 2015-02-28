package com.keybox.manage.util;


import com.keybox.common.util.AppConfig;
import com.keybox.manage.db.AuthDB;
import com.keybox.manage.db.UserDB;
import com.keybox.manage.model.Auth;
import com.keybox.manage.model.User;
import org.apache.commons.lang3.StringUtils;

import javax.security.auth.callback.*;
import javax.security.auth.login.LoginContext;
import javax.security.auth.login.LoginException;
import java.io.IOException;
import java.sql.Connection;
import java.util.UUID;

public class ExternalAuthUtil {



    public static final boolean externalAuthEnabled = StringUtils.isNotEmpty(AppConfig.getProperty("jaasModule"));
    private static final String JAAS_CONF = "jaas.conf";
    private static final String JAAS_MODULE = AppConfig.getProperty("jaasModule");


    static {
        if(externalAuthEnabled) {
            System.setProperty("java.security.auth.login.config", ExternalAuthUtil.class.getClassLoader().getResource(".").getPath() + JAAS_CONF);
        }
    }
    
   

    /**
     * external auth login method
     *
     * @param auth contains username and password
     * @return auth token if success
     */
    public static String login(final Auth auth) {

        String authToken = null;
        if (externalAuthEnabled && auth != null && StringUtils.isNotEmpty(auth.getUsername()) && StringUtils.isNotEmpty(auth.getPassword())) {

            Connection con = null;
            try {
                CallbackHandler handler = new CallbackHandler() {

                    @Override
                    public void handle(Callback[] callbacks) throws IOException,
                            UnsupportedCallbackException {
                        for (Callback callback : callbacks) {
                            if (callback instanceof NameCallback) {
                                ((NameCallback) callback).setName(auth
                                        .getUsername());
                            } else if (callback instanceof PasswordCallback) {
                                ((PasswordCallback) callback).setPassword(auth
                                        .getPassword().toCharArray());
                            }
                        }
                    }
                };

                try {
                    LoginContext loginContext = new LoginContext(JAAS_MODULE, handler);
                    //will throw exception if login fail
                    loginContext.login();

                    con = DBUtils.getConn();
                    User user = AuthDB.getUserByUID(con, auth.getUsername());

                    if (user == null) {
                        user = new User();

                        user.setUserType(User.ADMINISTRATOR);
                        user.setUsername(auth.getUsername());

                        user.setId(UserDB.insertUser(con, user));
                    }

                    authToken = UUID.randomUUID().toString();
                    user.setAuthToken(authToken);
                    user.setAuthType(Auth.AUTH_EXTERNAL);
                    //set auth token
                    AuthDB.updateLogin(con, user);


                } catch (LoginException e) {
                    //auth failed return empty
                    authToken = null;
                }
            } catch (Exception e) {
                e.printStackTrace();
            }

            DBUtils.closeConn(con);
        }

       



        return authToken;
    }
}

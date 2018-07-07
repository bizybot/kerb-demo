package org.elasticsearch.xpack.client.demo.controller;

import java.io.IOException;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import javax.security.auth.Subject;
import javax.security.auth.login.LoginContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.http.HttpHost;
import org.elasticsearch.action.main.MainResponse;
import org.elasticsearch.client.RestClient;
import org.elasticsearch.client.RestClientBuilder;
import org.elasticsearch.client.RestHighLevelClient;
import org.elasticsearch.common.settings.SecureString;
import org.elasticsearch.xpack.client.demo.kerberos.support.CustomHttpClientConfigCallbackHandler;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.servlet.ModelAndView;

@Controller
public class NodeInfoController {
    @Value("${es}")
    private String es;
    @Value("${user.keytab.principal}")
    private String userKeytabPrincipal;
    @Value("${user.principal}")
    private String userPrincipal;
    @Value("${user.password}")
    private String userPassword;

    @GetMapping(value = "/node/info")
    public ModelAndView ninfo(HttpServletRequest request, HttpServletResponse response)
            throws IOException, PrivilegedActionException {

        final RestClientBuilder esRestClientBuilder = RestClient.builder(new HttpHost(es, 9200, "https"));
        boolean exampleWithKeytab = Boolean.parseBoolean(System.getProperty("useKeytab", "false"));
        CustomHttpClientConfigCallbackHandler configCallback = null;
        if (exampleWithKeytab) {
            configCallback = new CustomHttpClientConfigCallbackHandler(userKeytabPrincipal, null);
        } else {
            configCallback = new CustomHttpClientConfigCallbackHandler(userPrincipal, new SecureString(userPassword));
        }
        LoginContext loginContext = configCallback.login();
        esRestClientBuilder.setHttpClientConfigCallback(configCallback);
        try (RestHighLevelClient esRestClient = new RestHighLevelClient(esRestClientBuilder)) {
            return Subject.doAs(loginContext.getSubject(), new PrivilegedExceptionAction<ModelAndView>() {
                @Override
                public ModelAndView run() throws Exception {
                    return NodeInfoController.this.execute(esRestClient);
                }
            });
        }
    }

    ModelAndView execute(RestHighLevelClient esRestClient) throws IOException {
        MainResponse nodeInfoResponse = esRestClient.info();
        ModelAndView mavR = new ModelAndView();
        mavR.setStatus(HttpStatus.OK);
        mavR.addObject("tagline", "You Know, for Search - secured by kerberos");
        mavR.addObject("nodeName", nodeInfoResponse.getNodeName());
        mavR.addObject("version", nodeInfoResponse.getVersion().toString());
        mavR.addObject("clusterUUID", nodeInfoResponse.getClusterUuid());
        mavR.setViewName("nodeinfo");
        return mavR;
    }
}

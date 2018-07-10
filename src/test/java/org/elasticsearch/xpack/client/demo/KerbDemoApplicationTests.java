package org.elasticsearch.xpack.client.demo;

import java.io.IOException;
import java.security.PrivilegedActionException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.elasticsearch.xpack.client.demo.controller.NodeInfoController;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.servlet.ModelAndView;

@RunWith(SpringRunner.class)
@SpringBootTest
@TestPropertySource(locations="classpath:test-application.properties")
public class KerbDemoApplicationTests {
	@Autowired
	private NodeInfoController nodeInfoController;
	@Test
	public void contextLoads() {
	}

	@Test
	public void testLoginByPassword() throws IOException, PrivilegedActionException {
		ResourceLoader resourceLoader = new DefaultResourceLoader();
		Resource loginConf = resourceLoader.getResource("login.conf");
		Resource krb5Conf = resourceLoader.getResource("krb5.conf");
		System.setProperty("sun.security.krb5.debug", "true");
		System.setProperty("sun.security.spnego.debug", "true");
		System.setProperty("java.security.krb5.conf", krb5Conf.getFile().getAbsolutePath());
		System.setProperty("java.security.auth.login.config", loginConf.getFile().getAbsolutePath());
		HttpServletRequest request = new MockHttpServletRequest();
		HttpServletResponse response = new MockHttpServletResponse();
		ModelAndView mv = nodeInfoController.ninfo(request, response);
		Assert.assertEquals("7.0.0-alpha1", (String)mv.getModel().get("version"));
	}
}

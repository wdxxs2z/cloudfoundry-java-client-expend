package org.cloudfoundry.client.lib.rest;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.client.lib.CloudCredentials;
import org.cloudfoundry.client.lib.CloudFoundryClient;
import org.junit.Test;

public class ResourceTest {
	
	@Test
	public void testResource() {
		CloudCredentials credentials = new CloudCredentials("jackyuan88726@gmail.com", "12345679");
		URL cloudUrl = null;
		try {
			cloudUrl = new URL("https://api.run.pivotal.io");
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		CloudFoundryClient client = new CloudFoundryClient(credentials, cloudUrl, true);
		List<Map<String,Object>> allResourcesWithparams = client.getAllResourcesWithparams("/v2/organizations?", null);
//		String objectWithGuid = client.getOneObjectWithGuid("/v2/organizations/4f7edc60-17cf-458b-9881-a8e7464f9166");
//		Map<String, Object> oneObjectWithParams = client.getCloudEntity("quota_definitions", "default", "0");
//		List<Map<String, Object>> apps = client.getCloudResources("apps", "1");
//		Map<String,String> prefixMap = new HashMap<String, String>();
//		prefixMap.put("spaces", "mycloud");
//		client.getCloudResourcesWithPrefix(prefixMap, "apps", "1");
		Map<String,String> prefixMap = new HashMap<String, String>();
		prefixMap.put("services", "elephantsql");
		client.getCloudEntityWithPrefix(prefixMap, "service_plans", "Tiny-Turtle", "1");
	}

}

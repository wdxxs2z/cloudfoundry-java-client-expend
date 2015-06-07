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
		CloudCredentials credentials = new CloudCredentials("facebook", "12345678");
		URL cloudUrl = null;
		try {
//			cloudUrl = new URL("https://api.run.pivotal.io");
			cloudUrl = new URL("https://api.192.168.172.133.xip.io");
		} catch (MalformedURLException e) {
			e.printStackTrace();
		}
		CloudFoundryClient client = new CloudFoundryClient(credentials, cloudUrl, true);
//		List<Map<String,Object>> allResourcesWithparams = client.getAllResourcesWithparams("/v2/organizations?", null);
////		String objectWithGuid = client.getOneObjectWithGuid("/v2/organizations/4f7edc60-17cf-458b-9881-a8e7464f9166");
////		Map<String, Object> oneObjectWithParams = client.getCloudEntity("quota_definitions", "default", "0");
////		List<Map<String, Object>> apps = client.getCloudResources("apps", "1");
////		Map<String,String> prefixMap = new HashMap<String, String>();
////		prefixMap.put("spaces", "mycloud");
////		client.getCloudResourcesWithPrefix(prefixMap, "apps", "1");
//		Map<String,String> prefixMap = new HashMap<String, String>();
//		prefixMap.put("services", "elephantsql");
//		List<Map<String, Object>> resources = client.getCloudResourcesWithPrefix(prefixMap, "service_plans", "1");
//		prefixMap.clear();
//		prefixMap.put("spaces", "development");
//		client.getCloudEntityWithPrefix(prefixMap, "services", "elephantsql", "1");
////		client.getCloudEntityWithPrefix(prefixMap, "service_instances", "jojopost", "1");
//		String resources = client.getCloudStringResources("users", "0");
//		long last = System.currentTimeMillis();
//		System.out.println(last);
//		String guid = client.getObjectGuid("users", "facebook");
//		long first = System.currentTimeMillis();
//		System.out.println(first);
//		System.out.println(first - last);
//		System.out.println(resources);
//		System.out.println(guid);
//		for (int i=0 ; i<1000 ; i++) {
//			client.createUser("jojo-" + i, "12345678", "jojo-" + i, "jojo-" + i, i + "");
//		}
//		for (int i=0 ; i<1000 ; i++) {
//			client.deleteUserWithUserName("jojo-" + i);
//		}
//		long first = System.currentTimeMillis();
//		String guid = client.getObjectGuid("users", "jojo-2");
//		long last = System.currentTimeMillis();
//		System.out.println(last - first);
//		System.out.println(guid);
//		for (int i=0 ; i<1000 ; i++) {
//			client.deleteUserWithUserName("jojo-" + i);
//		}
	}

}

/*
 * Copyright 2009-2012 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.cloudfoundry.client.lib.oauth2;

import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.cloudfoundry.client.lib.CloudCredentials;
import org.cloudfoundry.client.lib.CloudFoundryException;
import org.cloudfoundry.client.lib.domain.CloudUser;
import org.cloudfoundry.client.lib.util.JsonUtil;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.password.ResourceOwnerPasswordResourceDetails;
import org.springframework.security.oauth2.common.AuthenticationScheme;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.client.RestTemplate;

/**
 * Client that can handle authentication against a UAA instance
 *
 * @author Dave Syer
 * @author Thomas Risberg
 */
public class OauthClient {

	private static final String AUTHORIZATION_HEADER_KEY = "Authorization";

	private URL authorizationUrl;

	private RestTemplate restTemplate;

	private OAuth2AccessToken token;
	private CloudCredentials credentials;

	public OauthClient(URL authorizationUrl, RestTemplate restTemplate) {
		this.authorizationUrl = authorizationUrl;
		this.restTemplate = restTemplate;
	}

	public void init(CloudCredentials credentials) {
		if (credentials != null) {
			this.credentials = credentials;

			if (credentials.getToken() != null) {
				this.token = credentials.getToken();
			} else {
				this.token = createToken(credentials.getEmail(), credentials.getPassword(),
						credentials.getClientId(), credentials.getClientSecret());
			}
		}
	}

	public void clear() {
		this.token = null;
		this.credentials = null;
	}

	public OAuth2AccessToken getToken() {
		if (token == null) {
			return null;
		}

		if (token.getExpiresIn() < 50) { // 50 seconds before expiration? Then refresh it.
			token = refreshToken(token, credentials.getEmail(), credentials.getPassword(),
					credentials.getClientId(), credentials.getClientSecret());
		}

		return token;
	}

	public String getAuthorizationHeader() {
		OAuth2AccessToken accessToken = getToken();
		if (accessToken != null) {
			return accessToken.getTokenType() + " " + accessToken.getValue();
		}
		return null;
	}

	private OAuth2AccessToken createToken(String username, String password, String clientId, String clientSecret) {
		OAuth2ProtectedResourceDetails resource = getResourceDetails(username, password, clientId, clientSecret);
		AccessTokenRequest request = createAccessTokenRequest(username, password);

		ResourceOwnerPasswordAccessTokenProvider provider = createResourceOwnerPasswordAccessTokenProvider();
		try {
			return provider.obtainAccessToken(resource, request);
		}
		catch (OAuth2AccessDeniedException oauthEx) {
			HttpStatus status = HttpStatus.valueOf(oauthEx.getHttpErrorCode());
			CloudFoundryException cfEx = new CloudFoundryException(status, oauthEx.getMessage());
			cfEx.setDescription(oauthEx.getSummary());
			throw cfEx;
		}
	}

	private OAuth2AccessToken refreshToken(OAuth2AccessToken currentToken, String username, String password, String clientId, String clientSecret) {
		OAuth2ProtectedResourceDetails resource = getResourceDetails(username, password, clientId, clientSecret);
		AccessTokenRequest request = createAccessTokenRequest(username, password);

		ResourceOwnerPasswordAccessTokenProvider provider = createResourceOwnerPasswordAccessTokenProvider();

		return provider.refreshAccessToken(resource, currentToken.getRefreshToken(), request);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	public void changePassword(String oldPassword, String newPassword) {
		HttpHeaders headers = new HttpHeaders();
		headers.add(AUTHORIZATION_HEADER_KEY, token.getTokenType() + " " + token.getValue());
		HttpEntity info = new HttpEntity(headers);
		ResponseEntity<String> response = restTemplate.exchange(authorizationUrl + "/userinfo", HttpMethod.GET, info, String.class);
		Map<String, Object> responseMap = JsonUtil.convertJsonToMap(response.getBody());
		String userId = (String) responseMap.get("user_id");
		Map<String, Object> body = new HashMap<String, Object>();
		body.put("schemas", new String[] {"urn:scim:schemas:core:1.0"});
		body.put("password", newPassword);
		body.put("oldPassword", oldPassword);
		HttpEntity<Map> httpEntity = new HttpEntity<Map>(body, headers);
		restTemplate.put(authorizationUrl + "/User/{id}/password", httpEntity, userId);
	}

	protected ResourceOwnerPasswordAccessTokenProvider createResourceOwnerPasswordAccessTokenProvider() {
		ResourceOwnerPasswordAccessTokenProvider resourceOwnerPasswordAccessTokenProvider = new ResourceOwnerPasswordAccessTokenProvider();
		resourceOwnerPasswordAccessTokenProvider.setRequestFactory(restTemplate.getRequestFactory()); //copy the http proxy along
		return resourceOwnerPasswordAccessTokenProvider;
	}

	private AccessTokenRequest createAccessTokenRequest(String username, String password) {
		AccessTokenRequest request = new DefaultAccessTokenRequest();
		return request;
	}

	private OAuth2ProtectedResourceDetails getResourceDetails(String username, String password, String clientId, String clientSecret) {
		ResourceOwnerPasswordResourceDetails resource = new ResourceOwnerPasswordResourceDetails();
		resource.setUsername(username);
		resource.setPassword(password);

		resource.setClientId(clientId);
		resource.setClientSecret(clientSecret);
		resource.setId(clientId);
		resource.setClientAuthenticationScheme(AuthenticationScheme.header);
		resource.setAccessTokenUri(authorizationUrl + "/oauth/token");

		return resource;
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public String getUserName(String uuid){
		HttpHeaders headers = new HttpHeaders();
		headers.add(AUTHORIZATION_HEADER_KEY, token.getTokenType() + " " + token.getValue());
		HttpEntity info = new HttpEntity(headers);
		ResponseEntity<String> response = restTemplate.exchange(authorizationUrl + "/Users?attributes=userName&filter=id eq " + "'" + uuid + "'", HttpMethod.GET, info, String.class);
		Map<String, Object> responseMap = JsonUtil.convertJsonToMap(response.getBody());
		ArrayList<Map<String, Object>> resources =  (ArrayList<Map<String, Object>>) responseMap.get("resources");
		for(Map<String, Object> resource : resources){
			if(resource.containsKey("userName")){
				return (String) resource.get("userName");
			}
		}
		return null;
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public String getUserIdByName(String userName){
		HttpHeaders headers = new HttpHeaders();
		headers.add(AUTHORIZATION_HEADER_KEY, token.getTokenType() + " " + token.getValue());
		HttpEntity info = new HttpEntity(headers);
		ResponseEntity<String> response = restTemplate.exchange(authorizationUrl + "/Users?attributes=id&filter=userName eq " + "'" + userName + "'", HttpMethod.GET, info, String.class);
		Map<String, Object> responseMap = JsonUtil.convertJsonToMap(response.getBody());
		ArrayList<Map<String, Object>> resources =  (ArrayList<Map<String, Object>>) responseMap.get("resources");
		for(Map<String, Object> resource : resources){
			if(resource.containsKey("id")){
				return (String) resource.get("id");
			}
		}
		return null;		
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	public Map<String,Object> getUserInfo(String uuid){
		HttpHeaders headers = new HttpHeaders();
		headers.add(AUTHORIZATION_HEADER_KEY, token.getTokenType() + " " + token.getValue());
		HttpEntity info = new HttpEntity(headers);
		//ResponseEntity<String> response = restTemplate.exchange(authorizationUrl + "/Users?attributes=userName,name,emails,phoneNumbers&filter=id eq " + "'" + uuid + "'", HttpMethod.GET, info, String.class);
		ResponseEntity<String> response = restTemplate.exchange(authorizationUrl + "/Users?filter=id eq " + "'" + uuid + "'", HttpMethod.GET, info, String.class);		
		Map<String, Object> responseMap = JsonUtil.convertJsonToMap(response.getBody());
		ArrayList<Map<String, Object>> resources =  (ArrayList<Map<String, Object>>) responseMap.get("resources");
		Map<String,Object> usermap = new HashMap<String, Object>();
		for(Map<String, Object> resource : resources){
			if(resource.containsKey("userName")){
				usermap.put("userName", resource.get("userName"));
			}
			if(resource.containsKey("name")){
				Map<String,String> names = (Map<String, String>) resource.get("name");
				usermap.put("familyName", names.get("familyName"));
				usermap.put("givenName",names.get("givenName"));
			}
			if(resource.containsKey("emails")){	
				usermap.put("emails", resource.get("emails"));
			}
			if(resource.containsKey("phoneNumbers")){
				usermap.put("phoneNumbers", resource.get("phoneNumbers"));
			}else{
				usermap.put("phoneNumbers", null);
			}
		}
		return usermap;
	}

	public String createUser(String username, String password, String familyName, String givenName, String phoneNumber) {
		HttpHeaders headers = new HttpHeaders();
		headers.add(AUTHORIZATION_HEADER_KEY, token.getTokenType() + " " + token.getValue());
		headers.add("Content-Type", "application/json;charset=utf-8");
		headers.add("accept", "application/json");
		Map<String, Object> body = new HashMap<String, Object>();
		
		Map<String, Object> name = new HashMap<String, Object>();
		name.put("familyName", familyName);
		name.put("givenName", givenName);
		
		ArrayList<Map<String, Object>> emails = new ArrayList<Map<String,Object>>();
		Map<String,Object> email = new HashMap<String, Object>();
		email.put("value", username);
		emails.add(email);
		
		ArrayList<Map<String, Object>> phoneNumbers = new ArrayList<Map<String,Object>>();
		Map<String,Object> phone = new HashMap<String, Object>();
		phone.put("value", phoneNumber);
		phoneNumbers.add(phone);
		
		body.put("userName", username);
		body.put("emails", emails);
		body.put("password", password);
		body.put("name", name);
		body.put("phoneNumbers", phoneNumbers);
		
		String jsonBody = JsonUtil.convertToJson(body);
		HttpEntity<String> httpEntity = new HttpEntity<String>(jsonBody, headers);
		
		//HttpEntity<Map> httpEntity = new HttpEntity<Map>(body, headers);
		ResponseEntity<String> response = restTemplate.postForEntity(authorizationUrl + "/Users", httpEntity, String.class);
		Map<String, Object> responseMap = JsonUtil.convertJsonToMap(response.getBody());
		String UID = (String) responseMap.get("id");	
		return UID;
	}
	
	public void updateUser(CloudUser cloudUser){	
		String user_id = cloudUser.getMeta().getGuid().toString();
		String username = cloudUser.getName();
		String familyName = cloudUser.getFamilyName();
		String givenName = cloudUser.getGivenName();
		List<String> emails = cloudUser.getEmails();
		List<String> phoneNumbers = cloudUser.getPhoneNumbers();
		
		HttpHeaders headers = new HttpHeaders();
		headers.add(AUTHORIZATION_HEADER_KEY, token.getTokenType() + " " + token.getValue());
		headers.add("Content-Type", "application/json;charset=utf-8");
		headers.add("accept", "application/json");
		Map<String, Object> body = new HashMap<String, Object>();
		
		Map<String, Object> name = new HashMap<String, Object>();
		name.put("familyName", familyName);
		name.put("givenName", givenName);
		
		body.put("userName", username);
		body.put("emails", emails);
		body.put("name", name);
		body.put("phoneNumbers", phoneNumbers);
		
		String jsonBody = JsonUtil.convertToJson(body);
		HttpEntity<String> httpEntity = new HttpEntity<String>(jsonBody, headers);
		restTemplate.put(authorizationUrl + "/Users/" + user_id, httpEntity);		
	}
	
	public void approveUser(String userName, String displayName, String member_type, String authorities){
		
		HttpHeaders headers = new HttpHeaders();
		headers.add(AUTHORIZATION_HEADER_KEY, token.getTokenType() + " " + token.getValue());
		headers.add("Content-Type", "application/json;charset=utf-8");
		headers.add("accept", "application/json;charset=utf-8");
		Map<String, Object> body = new HashMap<String, Object>();
		
		String member_id = this.getUserIdByName(userName);
		
		body.put("schemas", new String[] {"urn:scim:schemas:core:1.0"});
		body.put("displayName", displayName);
		
		List<Map<String,Object>> members = new ArrayList<Map<String,Object>>();
		
		Map<String,Object> memberMap = new HashMap<String, Object>();
		memberMap.put("type", member_type);		
		memberMap.put("origin", authorities);
		memberMap.put("value", member_id);
		
		members.add(memberMap);
		
		body.put("members", members);
		
		String jsonBody = JsonUtil.convertToJson(body);
		HttpEntity<String> httpEntity = new HttpEntity<String>(jsonBody, headers);
		restTemplate.postForEntity(authorizationUrl + "/Groups", httpEntity, String.class);
	}
	
	public void updateGroupMemberByUserGuid(String userGuid, String displayName, String member_type, Boolean isDelete){
		String userName = this.getUserName(userGuid);
		this.updateGroupMember(userName, displayName, member_type, isDelete);
	}
	
	@SuppressWarnings("unchecked")
	public void updateGroupMember(String userName, String displayName, String member_type, Boolean isDelete){
		
		final String MEMTYPE = "members";
		final String READERTYPE = "readers";
		final String WRITERTYPE = "writers";
		
		Map<String, Object> groupInfo = this.getGroupInfo(displayName, null);
		if (groupInfo == null){
			return;
		}
		
		Map<String,Object> meta = (Map<String, Object>) groupInfo.get("meta");
		Integer version = (Integer) meta.get("version");
		
		HttpHeaders headers = new HttpHeaders();
		headers.add(AUTHORIZATION_HEADER_KEY, token.getTokenType() + " " + token.getValue());
		headers.add("Content-Type", "application/json;charset=utf-8");
		headers.add("accept", "application/json;charset=utf-8");
		headers.add("if-match", version.toString());
		Map<String, Object> body = new HashMap<String, Object>();
				
		//group id
		String group_id = (String) groupInfo.get("id");
		//user id
		String user_id = this.getUserIdByName(userName);				
		
		//userList
		List<String> userVlaues = new ArrayList<String>();
		
		if (member_type == MEMTYPE) {
			Boolean isexist = false;
			if (groupInfo.get("members") != null) {
				List<Map<String,Object>> members = (List<Map<String, Object>>) groupInfo.get("members");
				for (Map<String,Object> member : members) {
					String member_id = (String) member.get("value");
					userVlaues.add(member_id);
					if (member_id.endsWith(user_id)) {
						isexist = true;
					}
				}
				if (isDelete == true && isexist == true) {
					userVlaues.remove(user_id);
					body.put("members", userVlaues);
				} else if (isexist == false && isDelete == true){
					return;
				} else if (isexist == false && isDelete == false) {
					userVlaues.add(user_id);
					body.put("members", userVlaues);
				}				
			}else{
				if (isDelete == true) {
					return;
				} else {
					userVlaues.add(user_id);
					body.put("members", userVlaues);
				}				
			}
			//Other will be keep 
			if (groupInfo.get("readers") != null) {
				body.put("readers", groupInfo.get("readers"));
			}
			if (groupInfo.get("writers") != null) {
				body.put("writers", groupInfo.get("writers"));
			}
		}
		
		if (member_type == READERTYPE) {
			Boolean isexist = false;
			if (groupInfo.get("readers") != null) {
				List<Map<String,Object>> readers = (List<Map<String, Object>>) groupInfo.get("readers");
				for (Map<String,Object> reader : readers) {
					String reader_id = (String) reader.get("value");
					userVlaues.add(reader_id);
					if (reader_id.endsWith(user_id)) {
						isexist = true;
					}
				}
				if (isDelete == true && isexist == true) {
					userVlaues.remove(user_id);
					body.put("readers", userVlaues);
				} else if (isexist == false && isDelete == true){
					return;
				} else if (isexist == false && isDelete == false) {
					userVlaues.add(user_id);
					body.put("readers", userVlaues);
				}
			}else{
				if (isDelete == true) {
					return;
				} else {
					userVlaues.add(user_id);
					body.put("readers", userVlaues);
				}				
			}
			//Other will be keep 
			if (groupInfo.get("members") != null) {
				body.put("members", groupInfo.get("members"));
			}
			if (groupInfo.get("writers") != null) {
				body.put("writers", groupInfo.get("writers"));
			}
		}
		if (member_type == WRITERTYPE) {
			Boolean isexist = false;
			if (groupInfo.get("writers") != null) {
				List<Map<String,Object>> writers = (List<Map<String, Object>>) groupInfo.get("writers");
				for (Map<String,Object> write : writers) {
					String writer_id = (String) write.get("value");
					userVlaues.add(writer_id);
					if (writer_id.endsWith(user_id)) {
						isexist = true;
					}
				}
				if (isDelete == true && isexist == true) {
					userVlaues.remove(user_id);
					body.put("writers", userVlaues);
				} else if (isexist == false && isDelete == true){
					return;
				} else if (isexist == false && isDelete == false) {
					userVlaues.add(user_id);
					body.put("writers", userVlaues);
				}
			}else{
				if (isDelete == true) {
					return;
				} else {
					userVlaues.add(user_id);
					body.put("writers", userVlaues);
				}				
			}
			//Other will be keep 
			if (groupInfo.get("members") != null) {
				body.put("members", groupInfo.get("members"));
			}
			if (groupInfo.get("readers") != null) {
				body.put("readers", groupInfo.get("readers"));
			}
		}
						
		body.put("schemas", new String[] {"urn:scim:schemas:core:1.0"});
		body.put("id", group_id);
		body.put("displayName", displayName);
		body.put("meta", meta);
		
		String jsonBody = JsonUtil.convertToJson(body);
		HttpEntity<String> httpEntity = new HttpEntity<String>(jsonBody, headers);
		restTemplate.put(authorizationUrl + "/Groups/" + group_id, httpEntity);		
	}
	
	@SuppressWarnings("unchecked")
	public Boolean isMemberByUserAndDisplayName(String user_id, String displayName){
		Boolean flag= false;
		Map<String, Object> groupInfo = getGroupInfo(displayName, null);
		if (groupInfo.get("members") != null) {
			List<Map<String,Object>> members = (List<Map<String, Object>>) groupInfo.get("members");
			for (Map<String,Object> member : members) {
				String member_id = (String) member.get("value");
				if (member_id.endsWith(user_id)) {
					flag = true;
				}
			}
		}
		return flag;
	}
	
	@SuppressWarnings("unchecked")
	public Boolean isWriterByUserAndDisplayName(String user_id, String displayName){
		Boolean flag= false;
		Map<String, Object> groupInfo = getGroupInfo(displayName, null);
		if (groupInfo.get("writers") != null) {
			List<Map<String,Object>> writers = (List<Map<String, Object>>) groupInfo.get("writers");
			for (Map<String,Object> writer : writers) {
				String writer_id = (String) writer.get("value");
				if (writer_id.endsWith(user_id)) {
					flag = true;
				}
			}
		}
		return flag;
	}
	
	@SuppressWarnings("unchecked")
	public Boolean isReaderByUserAndDisplayName(String user_id, String displayName){
		Boolean flag= false;
		Map<String, Object> groupInfo = getGroupInfo(displayName, null);
		if (groupInfo.get("readers") != null) {
			List<Map<String,Object>> readers = (List<Map<String, Object>>) groupInfo.get("readers");
			for (Map<String,Object> reader : readers) {
				String reader_id = (String) reader.get("value");
				if (reader_id.endsWith(user_id)) {
					flag = true;
				}
			}
		}
		return flag;
	}
	
	@SuppressWarnings({ "rawtypes", "unchecked" })
	protected Map<String,Object> getGroupInfo(String displayName, List<String> attributes) {
		
		StringBuffer url = new StringBuffer();
		url.append("/Groups?");
		if (attributes != null) {
			url.append("attributes=");
			for(int i=0;i<attributes.size();i++){
				if (i == attributes.size()-1) {
					url.append(attributes.get(i));
				}else{
					url.append(attributes.get(i)).append(",");
				}
			}
			url.append("&filter=displayName Eq " + "\"" + displayName + "\"");
		}else{
			url.append("filter=displayName Eq " + "\"" + displayName + "\"");
		}
		
		HttpHeaders headers = new HttpHeaders();
		headers.add(AUTHORIZATION_HEADER_KEY, token.getTokenType() + " " + token.getValue());
		headers.add("accept", "application/json;charset=utf-8");
		HttpEntity info = new HttpEntity(headers);

		
		ResponseEntity<String> response = restTemplate.exchange(authorizationUrl + url.toString(), HttpMethod.GET, info, String.class);
		
		
		Map<String, Object> responseMap = JsonUtil.convertJsonToMap(response.getBody());
		ArrayList<Map<String, Object>> resources =  (ArrayList<Map<String, Object>>) responseMap.get("resources");
		
		Map<String,Object> groupResource = new HashMap<String, Object>();
		for(Map<String, Object> resource : resources){
			if(resource.containsKey("id")){
				groupResource.put("id", resource.get("id"));
			}
			if(resource.containsKey("displayName")){
				groupResource.put("displayName", resource.get("displayName"));
			}
			if(resource.containsKey("members")){				
				List<Map<String,Object>> members = (List<Map<String, Object>>) resource.get("members");
				groupResource.put("members", members);
			}
			if(resource.containsKey("readers")){
				List<Map<String,Object>> readers = (List<Map<String, Object>>) resource.get("readers");
				groupResource.put("readers", readers);
			}
			if(resource.containsKey("writers")){
				List<Map<String,Object>> writers = (List<Map<String, Object>>) resource.get("writers");
				groupResource.put("writers", writers);
			}
			if(resource.containsKey("meta")){
				groupResource.put("meta", resource.get("meta"));
			}
		}
		
		if(groupResource.size() == 0){
			return groupResource;
		}
		
		return groupResource;
	}
}

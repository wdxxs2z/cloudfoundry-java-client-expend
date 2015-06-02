/*
 * Copyright 2009-2013 the original author or authors.
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

package org.cloudfoundry.client.lib;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.cloudfoundry.client.lib.archive.ApplicationArchive;
import org.cloudfoundry.client.lib.domain.ApplicationLog;
import org.cloudfoundry.client.lib.domain.ApplicationStats;
import org.cloudfoundry.client.lib.domain.CloudAdminBuildpack;
import org.cloudfoundry.client.lib.domain.CloudApplication;
import org.cloudfoundry.client.lib.domain.CloudDomain;
import org.cloudfoundry.client.lib.domain.CloudEvent;
import org.cloudfoundry.client.lib.domain.CloudInfo;
import org.cloudfoundry.client.lib.domain.CloudOrganization;
import org.cloudfoundry.client.lib.domain.CloudQuota;
import org.cloudfoundry.client.lib.domain.CloudRoute;
import org.cloudfoundry.client.lib.domain.CloudSecurityGroup;
import org.cloudfoundry.client.lib.domain.CloudSecurityRules;
import org.cloudfoundry.client.lib.domain.CloudService;
import org.cloudfoundry.client.lib.domain.CloudServiceBroker;
import org.cloudfoundry.client.lib.domain.CloudServiceInstance;
import org.cloudfoundry.client.lib.domain.CloudServiceOffering;
import org.cloudfoundry.client.lib.domain.CloudSpace;
import org.cloudfoundry.client.lib.domain.CloudSpaceQuota;
import org.cloudfoundry.client.lib.domain.CloudStack;
import org.cloudfoundry.client.lib.domain.CloudUser;
import org.cloudfoundry.client.lib.domain.CrashesInfo;
import org.cloudfoundry.client.lib.domain.InstancesInfo;
import org.cloudfoundry.client.lib.domain.Staging;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.web.client.ResponseErrorHandler;

/**
 * The interface defining operations making up the Cloud Foundry Java client's API.
 *
 * @author Ramnivas Laddad
 * @author A.B.Srinivasan
 * @author Jennifer Hickey
 * @author Dave Syer
 * @author Thomas Risberg
 * @author Alexander Orlov
 */
public interface CloudFoundryOperations {

	/**
	 * Override the default REST response error handler with a custom error handler.
	 *
	 * @param errorHandler
	 */
	void setResponseErrorHandler(ResponseErrorHandler errorHandler);

	/**
	 * Get the URL used for the cloud controller.
	 *
	 * @return the cloud controller URL
	 */
	URL getCloudControllerUrl();

	/**
	 * Get CloudInfo for the current cloud.
	 *
	 * @return CloudInfo object containing the cloud info
	 */
	CloudInfo getCloudInfo();

	/**
	 * Get list of CloudSpaces for the current cloud.
	 *
	 * @return List of CloudSpace objects containing the space info
	 */
	List<CloudSpace> getSpaces();

	/**
	 * Get list of CloudOrganizations for the current cloud.
	 *
	 * @return List of CloudOrganizations objects containing the organization info
	 */
	List<CloudOrganization> getOrganizations();

	/**
	 * Register new user account with the provided credentials.
	 *
	 * @param email the email account
	 * @param password the password
	 */
	void register(String email, String password);

	/**
	 * Update the password for the logged in user.
	 *
	 * @param newPassword the new password
	 */
	void updatePassword(String newPassword);

	/**
	 * Update the password for the logged in user using
	 * the username/old_password provided in the credentials.
	 *
	 * @param credentials current credentials
	 * @param newPassword the new password
	 */
	void updatePassword(CloudCredentials credentials, String newPassword);

	/**
	 * Unregister and log out the currently logged in user
	 */
	void unregister();

	/**
	 * Login using the credentials already set for the client.
	 *
	 * @return authentication token
	 */
	OAuth2AccessToken login();

	/**
	 * Logout closing the current session.
	 */
	void logout();

	/**
	 * Get all cloud applications.
	 *
	 * @return list of cloud applications
	 */
	List<CloudApplication> getApplications();

	/**
	 * Get cloud application with the specified name.
	 *
	 * @param appName name of the app
	 * @return the cloud application
	 */
	CloudApplication getApplication(String appName);

	/**
	 * Get application stats for the app with the specified name.
	 *
	 * @param appName name of the app
	 * @return the cloud application stats
	 */
	ApplicationStats getApplicationStats(String appName);

	/**
	 * Create application.
	 *
	 * @param appName application name
	 * @param staging staging info
	 * @param memory memory to use in MB
	 * @param uris list of URIs for the app
	 * @param serviceNames list of service names to bind to app
	 */
	void createApplication(String appName, Staging staging, Integer memory, List<String> uris,
                           List<String> serviceNames);

	/**
	 * Create application.
	 *
	 * @param appName      application name
	 * @param staging      staging info
	 * @param disk         disk quota to use in MB
	 * @param memory       memory to use in MB
	 * @param uris         list of URIs for the app
	 * @param serviceNames list of service names to bind to app
	 */
	public void createApplication(String appName, Staging staging, Integer disk, Integer memory, List<String> uris,
	                              List<String> serviceNames);

	/**
	 * Create a service.
	 *
	 * @param service cloud service info
	 */
	void createService(CloudService service);

	/**
	 * Create a user-provided service.
	 *
	 * @param service cloud service info
	 * @param credentials the user-provided service credentials
	 */
	void createUserProvidedService(CloudService service, Map<String, Object> credentials);

	/**
	 * Delete routes that do not have any application which is assigned to them.
	 */
	List<CloudRoute> deleteOrphanedRoutes();

	/**
	 * Upload an application.
	 *
	 * @param appName application name
	 * @param file path to the application archive or folder
	 * @throws java.io.IOException
	 */
	void uploadApplication(String appName, String file) throws IOException;

	/**
	 * Upload an application to cloud foundry.
	 * @param appName the application name
	 * @param file the application archive or folder
	 * @throws java.io.IOException
	 */
	void uploadApplication(String appName, File file) throws IOException;

	/**
	 * Upload an application to cloud foundry.
	 * @param appName the application name
	 * @param file the application archive
	 * @param callback a callback interface used to provide progress information or <tt>null</tt>
	 * @throws java.io.IOException
	 */
	void uploadApplication(String appName, File file, UploadStatusCallback callback) throws IOException;

	/**
	 * Upload an application to cloud foundry.
	 * @param appName the application name
	 * @param archive the application archive
	 * @throws java.io.IOException
	 */
	void uploadApplication(String appName, ApplicationArchive archive) throws IOException;

	/**
	 * Upload an application to cloud foundry.
	 * @param appName the application name
	 * @param archive the application archive
	 * @param callback a callback interface used to provide progress information or <tt>null</tt>
	 * @throws java.io.IOException
	 */
	void uploadApplication(String appName, ApplicationArchive archive, UploadStatusCallback callback) throws IOException;

	/**
	 * Start application. May return starting info if the response obtained after the start request contains headers.
	 * If the response does not contain headers, null is returned instead.
	 *
	 * @param appName
	 *            name of application
	 * @return Starting info containing response headers, if headers are present in the response. If there are no headers, return null.
	 */
	StartingInfo startApplication(String appName);

	/**
	 * Debug application.
	 *
	 * @param appName name of application
	 * @param mode debug mode info
	 */
	void debugApplication(String appName, CloudApplication.DebugMode mode);

	/**
	 * Stop application.
	 *
	 * @param appName name of application
	 */
	void stopApplication(String appName);

	/**
	 * Restart application.
	 *
	 * @param appName name of application
	 */
	StartingInfo restartApplication(String appName);

	/**
	 * Delete application.
	 *
	 * @param appName name of application
	 */
	void deleteApplication(String appName);

	/**
	 * Delete all applications.
	 */
	void deleteAllApplications();

	/**
	 * Delete all services.
	 */
	void deleteAllServices();

	/**
	 * Update application disk quota.
	 *
	 * @param appName name of application
	 * @param disk new disk setting in MB
	 */
	void updateApplicationDiskQuota(String appName, int disk);

	/**
	 * Update application memory.
	 *
	 * @param appName name of application
	 * @param memory new memory setting in MB
	 */
	void updateApplicationMemory(String appName, int memory);

	/**
	 * Update application instances.
	 *
	 * @param appName name of application
	 * @param instances number of instances to use
	 */
	void updateApplicationInstances(String appName, int instances);

	/**
	 * Update application services.
	 *
	 * @param appName name of appplication
	 * @param services list of services that should be bound to app
	 */
	void updateApplicationServices(String appName, List<String> services);

	/**
	 * Update application staging information.
	 *
	 * @param appName name of appplication
	 * @param staging staging information for the app
	 */
	void updateApplicationStaging(String appName, Staging staging);

	/**
	 * Update application URIs.
	 *
	 * @param appName name of application
	 * @param uris list of URIs the app should use
	 */
	void updateApplicationUris(String appName, List<String> uris);

	/**
	 * Update application env using a map where the key specifies the name of the environment variable
	 * and the value the value of the environment variable..
	 *
	 * @param appName name of application
	 * @param env map of environment settings
	 */
	void updateApplicationEnv(String appName, Map<String, String> env);

	/**
	 * Update application env using a list of strings each with one environment setting.
	 *
	 * @param appName name of application
	 * @param env list of environment settings
	 */
	void updateApplicationEnv(String appName, List<String> env);


	/**
	 * Get logs from the deployed application. The logs
	 * will be returned in a Map keyed by the path of the log file
	 * (logs/stderr.log, logs/stdout.log).
	 * @param appName name of the application
	 * @return a Map containing the logs. The logs will be returned with the path to the log file used as the key and
	 * the full content of the log file will be returned as a String value for the corresponding key.
	 * @deprecated Use {@link #streamLogs(String, ApplicationLogListener)} or {@link #getRecentLogs(String)}
	 */
	Map<String, String> getLogs(String appName);
	
	/**
	 * Stream application logs produced <em>after</em> this method is called.
	 * 
	 * This method has 'tail'-like behavior. Every time there is a new log entry,
	 * it notifies the listener.
	 * 
	 * @param appName the name of the application
	 * @param listener listener object to be notified
	 * @return token than can be used to cancel listening for logs
	 */
	StreamingLogToken streamLogs(String appName, ApplicationLogListener listener);
	
	/**
	 * Stream recent log entries.
	 * 
	 * Stream logs that were recently produced for an app.
	 *
	 * @param appName the name of the application
	 * @return the list of recent log entries
	 */
	List<ApplicationLog> getRecentLogs(String appName);

	/**
	 * Get logs from most recent crash of the deployed application. The logs
	 * will be returned in a Map keyed by the path of the log file
	 * (logs/stderr.log, logs/stdout.log).
	 *
	 * @param appName name of the application
	 * @return a Map containing the logs. The logs will be returned with the path to the log file used as the key and
	 * the full content of the log file will be returned as a String value for the corresponding key.
	 * @deprecated Use {@link #streamLogs(String, ApplicationLogListener)} or {@link #getRecentLogs(String)}
	 */
	Map<String, String> getCrashLogs(String appName);
	
	/**
	 * Get the staging log while an application is starting. A null
	 * value indicates that no further checks for staging logs should occur as
	 * staging logs are no longer available.
	 * 
	 * @param info
	 *            starting information containing staging log file URL. Obtained
	 *            after starting an application.
	 * @param offset
	 *            starting position from where content should be retrieved.
	 * @return portion of the staging log content starting from the offset. It
	 *         may contain multiple lines. Returns null if no further content is
	 *         available.
	 */
	String getStagingLogs(StartingInfo info, int offset);


	/**
	 * Get the list of stacks available for staging applications.
	 *
	 * @return the list of available stacks
	 */
	List<CloudStack> getStacks();

	/**
	 * Get a stack by name.
	 *
	 * @param name the name of the stack to get
	 * @return the stack, or null if not found
	 */
	CloudStack getStack(String name);

	/**
	 * Get file from the deployed application.
	 *
	 * @param appName name of the application
	 * @param instanceIndex instance index
	 * @param filePath path to the file
	 * @return the contents of the file
	 */
	String getFile(String appName, int instanceIndex, String filePath);

	/**
	 * Get a the content, starting at a specific position, of a file from the deployed application.
	 *
	 * @param appName name of the application
	 * @param instanceIndex instance index
	 * @param filePath path to the file
	 * @param startPosition the starting position of the file contents (inclusive)
	 * @return the contents of the file
	 */
	String getFile(String appName, int instanceIndex, String filePath, int startPosition);

	/**
	 * Get a range of content of a file from the deployed application. The range begins at the specified startPosition
	 * and extends to the character at endPosition - 1.
	 *
	 * @param appName name of the application
	 * @param instanceIndex instance index
	 * @param filePath path to the file
	 * @param startPosition the starting position of the file contents (inclusive)
	 * @param endPosition the ending position of the file contents (exclusive)
	 * @return the contents of the file
	 */
	String getFile(String appName, int instanceIndex, String filePath, int startPosition, int endPosition);

	/**
	 * Get a the last bytes, with length as specified, of content of a file from the deployed application.
	 *
	 * @param appName name of the application
	 * @param instanceIndex instance index
	 * @param filePath path to the file
	 * @param length the length of the file contents to retrieve
	 * @return the contents of the file
	 */
	String getFileTail(String appName, int instanceIndex, String filePath, int length);

	/**
	 * Get list of cloud services.
	 *
	 * @return list of cloud services
	 */
	List<CloudService> getServices();

	/**
	 * Get cloud service.
	 *
	 * @param service name of service
	 * @return the cloud service info
	 */
	CloudService getService(String service);

	/**
	 * Delete cloud service.
	 *
	 * @param service name of service
	 */
	void deleteService(String service);

	/**
	 * Get all service offerings.
	 *
	 * @return list of service offerings
	 */
	List<CloudServiceOffering> getServiceOfferings();

	/**
	 * Get all service brokers.
	 *
	 * @return
	 */
	List<CloudServiceBroker> getServiceBrokers();

	/**
	 * Get a service broker.
	 *
	 * @param name the service broker name
	 * @return the service broker
	 */
	CloudServiceBroker getServiceBroker(String name);

	/**
	 * Create a service broker.
	 *
	 * @param serviceBroker cloud service broker info
	 */
	void createServiceBroker(CloudServiceBroker serviceBroker);

	/**
	 * Update a service broker (unchanged forces catalog refresh).
	 *
	 * @param serviceBroker cloud service broker info
	 */
	void updateServiceBroker(CloudServiceBroker serviceBroker);

	/**
	 * Delete a service broker.
	 *
	 * @param name the service broker name
	 */
	void deleteServiceBroker(String name);


	/**
	 * Service plans are private by default when a service broker's catalog is
	 * fetched/updated. This method will update the visibility of all plans for
	 * a broker to either public or private.
	 *
	 * @param name       the service broker name
	 * @param visibility true for public, false for private
	 */
	void updateServicePlanVisibilityForBroker(String name, boolean visibility);

	/**
	 * Associate (provision) a service with an application.
	 *
	 * @param appName the application name
	 * @param serviceName the service name
	 */
	void bindService(String appName, String serviceName);

	/**
	 * Un-associate (unprovision) a service from an application.
	 * @param appName the application name
	 * @param serviceName the service name
	 */
	void unbindService(String appName, String serviceName);

	/**
	 * Get application instances info for application.
	 *
	 * @param appName name of application.
	 * @return instances info
	 */
	InstancesInfo getApplicationInstances(String appName);

	/**
	 * Get application instances info for application.
	 *
	 * @param app the application.
	 * @return instances info
	 */
	InstancesInfo getApplicationInstances(CloudApplication app);

	/**
	 * Get crashes info for application.
	 * @param appName name of application
	 * @return crashes info
	 */
	CrashesInfo getCrashes(String appName);

	/**
	 * Rename an application.
	 *
	 * @param appName the current name
	 * @param newName the new name
	 */
	void rename(String appName, String newName);

	/**
	 * Get list of all domain registered for the current organization.
	 *
	 * @return list of domains
	 */
	List<CloudDomain> getDomainsForOrg();

	/**
	 * Get list of all private domains.
	 *
	 * @return list of private domains
	 */
	List<CloudDomain> getPrivateDomains();

	/**
	 * Get list of all shared domains.
	 *
	 * @return list of shared domains
	 */
	List<CloudDomain> getSharedDomains();

	/**
	 * Get list of all domain shared and private domains.
	 *
	 * @return list of domains
	 */
	List<CloudDomain> getDomains();

	/**
	 * Gets the default domain for the current org, which is the first shared domain.
	 *
	 * @return the default domain
	 */
	CloudDomain getDefaultDomain();

	/**
	 * Add a private domain in the current organization.
	 *
	 * @param domainName the domain to add
	 */
	void addDomain(String domainName);

	/**
	 * Delete a private domain in the current organization.
	 *
	 * @param domainName the domain to remove
	 * @deprecated alias for {@link #deleteDomain}
	 */
	void removeDomain(String domainName);

	/**
	 * Delete a private domain in the current organization.
	 *
	 * @param domainName the domain to delete
	 */
	void deleteDomain(String domainName);

	/**
	 * Get the info for all routes for a domain.
	 *
	 * @param domainName the domain the routes belong to
	 * @return list of routes
	 */
	List<CloudRoute> getRoutes(String domainName);

	/**
	 * Register a new route to the a domain.
	 *
	 * @param host the host of the route to register
	 * @param domainName the domain of the route to register
	 */
	void addRoute(String host, String domainName);

	/**
	 * Delete a registered route from the space of the current session.
	 *
	 * @param host the host of the route to delete
	 * @param domainName the domain of the route to delete
	 */
	void deleteRoute(String host, String domainName);

	/**
	 * Register a new RestLogCallback
	 *
	 * @param callBack the callback to be registered
	 */
	void registerRestLogListener(RestLogCallback callBack);

	/**
	 * Un-register a RestLogCallback
	 *
	 * @param callBack the callback to be un-registered
	 */
	void unRegisterRestLogListener(RestLogCallback callBack);
	
	/**
	 * Get quota by name
	 *
	 * @param quotaName
	 * @param required
	 * @return CloudQuota instance
	 */
	CloudQuota getQuotaByName(String quotaName, boolean required);


	/**
	 * Set quota to organization
	 *
	 * @param orgName
	 * @param quotaName
	 */
	void setQuotaToOrg(String orgName, String quotaName);

	/**
	 * Create quota
	 *
	 * @param quota
	 */
	void createQuota(CloudQuota quota);

	/**
	 * Delete quota by name
	 *
	 * @param quotaName
	 */
	void deleteQuota(String quotaName);

	/**
	 * Get quota definitions
	 *
	 * @return List<CloudQuota>
	 */
	List<CloudQuota> getQuotas();
	
	/**
	 * Get space quota Definitions
	 * */
	List<CloudSpaceQuota> getSpaceQuotas();
	
	/**
	 * Create spaceQuota Definitions
	 * */
	void createSpaceQuota(CloudSpaceQuota spaceQuota);
	
	/**
	 * Remove spaceQuota Definitions from Space
	 * */
	void removeSpaceFromSpaceQuota(String spaceQuotaName, String spaceName, String orgName);
	
	/**
	 * Associate Space with the Space Quota Definition
	 * */
	void associateSpaceWithSpaceQuota(String spaceQuotaName, String spaceName, String orgName);
	
	/**
	 * Update SpaceQuota
	 * */
	void updateSpaceQuota(CloudSpaceQuota spaceQuota);
	
	/**
	 * DeleteSpaceQuota
	 * */
	void deleteSpaceQuota(String spaceQuotaName);
	
	/**
	 * Get All SpaceQuota With Space
	 * */
	List<CloudSpaceQuota> getSpaceQuotaWithSpace(String spaceName, String orgName);
	
	/**
	 * get All Spaces With SpaceQuota
	 * */
	List<CloudSpace> getSpacesWithSpaceQuota(String spaceQuotaName);

	/**
	 * Update Quota definition
	 *
	 * @param quota
	 * @param name
	 */
	void updateQuota(CloudQuota quota, String name);
	
	/**
	 * Get Users by OrgName
	 * 
	 * @param orgName
	 * */
	List<CloudUser> getUsersByOrgName(String orgName);
	
	/**
	 * Get Users By role and OrgName
	 * */
	List<CloudUser> getUsersByOrgRole(String orgName,String roleName);
	
	/**
	 * Get Users By role and SpaceName
	 * */
	List<CloudUser> getUsersBySpaceRole(String spaceUUID,String roleName);
	
	/**
	 * Get All users
	 * */
	List<CloudUser> getAllUsers();
	
	/**
	 * Get Users Filter Some
	 * */
	List<CloudUser> getUserWithFileters(Map<String,Object> filters);
	
	/**
	 * Find User by userName
	 * */
	CloudUser findUserByUsername(String username);
	
	/**
	 * Create User
	 * */
	void createUser(String username, String password, String familyName, String givenName, String phoneNumber);
	
	/**
	 * Create User only Resister2Uaa
	 * */
	String registerUserOnly(String username, String password, String familyName, String givenName, String phoneNumber);	
	
	/**
	 * Update User
	 * */
	void updateUserWithUsername(String username, Map<String,Object> updateParams);
	
	/**
	 * approve User
	 * @param userName
	 * @param displayName
	 * @param member_type
	 * @param authorities
	 * */
	void approveUser(String userName, String displayName, String member_type, String authorities);
	
	/**
	 * updateGroupMember
	 * @param userName
	 * @param displayName | uaa.admin,cloud_controller.admin,scim.read,scim.write...
	 * @param member_type | members,readers,writers
	 * @param isDelete 
	 * */
	public void updateGroupMember(String userName, String displayName, String member_type, Boolean isDelete);
	
	/**
	 * updateGroupMemberByUserGuid
	 * @param userGuid
	 * @param displayName | uaa.admin,cloud_controller.admin,scim.read,scim.write...
	 * @param member_type | members,readers,writers
	 * @param isDelete 
	 * */
	public void updateGroupMemberByUserGuid(String userGuid, String displayName, String member_type, Boolean isDelete);
	
	/**
	 * Associate User with the Organization
	 * */
	void associateUserWithOrg(CloudOrganization organization,CloudUser user);
	
	/**
	 * Associate Organization with the User
	 * */
	void associateOrgWithUser(CloudUser user, CloudOrganization organization);
	
	/**
	 * Associate Organization with the User
	 * */
	void associateOrgWithUser(String userGuid, String orgGuid);
	
	/**
	 * Associate Space with the User
	 * */
	void associataSpaceWithUser(CloudUser user, CloudSpace space);
	
	/**
	 * Associate Space with the User
	 * */
	void associataSpaceWithUser(String userGuid, String spaceGuid);
	
	/**
	 * Associate Role Organization with the User
	 * */
	void associateOrgRoleWithUser(CloudUser user, CloudOrganization organization, String roleName);
	
	/**
	 * Associate Role Space with the User
	 * */
	void associateSpaceRoleWithUser(CloudUser user, CloudSpace space, String roleName);
	
	/**
	 * Remove User from the Organization
	 * */
	void removeUserFormOrg(CloudOrganization organization, CloudUser user);
	
	/**
	 * Remove Organization from the User
	 * */
	void removeOrgFromUser(CloudUser user, CloudOrganization organization);
	
	/**
	 * Remove Role Organization from the User
	 * */
	void removeRoleOrgFromUser(CloudUser user, CloudOrganization organization, String roleName);
	
	/**
	 * Remove Space from the User
	 * */
	void removeSpaceFromUser(CloudUser user, CloudSpace space);
	
	/**
	 * Remove Role Space from the User
	 * */
	void removeRoleSpaceFromUser(CloudUser user, CloudSpace space, String roleName);
	
	/**
	 * Get Spaces from Organization 
	 * @param orgName
	 * */
	List<CloudSpace> getSpaceFromOrgName(String orgName);
	
	/**
	 * Get Applications From Space
	 * @param spaceGuid
	 * */
	List<CloudApplication> getAppsFromSpaceName(String spaceGuid);
	
	/**
	 * Get Domains From OrgName
	 * @param orgName
	 * */
	List<CloudDomain> getDomainFromOrgName(String orgName);
	
	/**
	 * Get UserSummary From UserName
	 * @param userName
	 * */
	CloudUser getUsersummaryFromUserName(String userName);
	
	/**
	 * Is Member By UserAndDisplayName
	 * @param user_id
	 * @param displayName
	 * */
	Boolean isMemberByUserAndDisplayName(String user_id, String displayName);
	
	/**
	 * Is Reader By UserAndDisplayName
	 * @param user_id
	 * @param displayName
	 * */
	Boolean isReaderByUserAndDisplayName(String user_id, String displayName);
	
	/**
	 * Is Writer By UserAndDisplayName
	 * @param user_id
	 * @param displayName
	 * */
	Boolean isWriterByUserAndDisplayName(String user_id, String displayName);
	
	/**
	 * Create Organization
	 * @param organizationName
	 * @param orgQuotaName
	 * */
	void createOrganization(String organizationName, String orgQuotaName);
	
	/**
	 * Delete Organization
	 * @param organizationName
	 * */
	void deleteOrganization(String organizationName);
	
	/**
	 * Update Organization
	 * @param cloudOrganization
	 * @param orgQuotaName
	 * */
	void updateOrganization(CloudOrganization cloudOrganization, String orgQuotaName);
	
	/**
	 * Create Space
	 * @param spaceName
	 * @param organizationName
	 * */
	void createSpace(String spaceName, String organizationName);
	
	/**
	 * Delete Space
	 * @param spaceName
	 * @param organizationName
	 * */
	void deleteSpace(String spaceName, String organizationName);
	
	/**
	 * Update Space
	 * @param cloudSpace
	 * @param organizationName
	 * */
	void updateSpace(CloudSpace cloudSpace, String organizationName);
	
	/**
	 * List all Security Groups
	 * @return List<CloudSecurityGroup>
	 * */
	List<CloudSecurityGroup> getSecurityGroups();
	
	/**
	 * Creating a Security Group
	 * @param name
	 * @param cloudSecurityRules
	 * @param spaceName
	 * @param organizationName
	 * */
	void createSecurityGroup(String name, List<CloudSecurityRules> cloudSecurityRules, String spaceName, String organizationName);

	/**
	 * Associate Space with the Security Group
	 * @param securityName 
	 * @param spaceName
	 * @param orgName
	 * */
	void setSpaceWithSecurityGroup(String securityName, String spaceName, String orgName);
	
	/**
	 * Associate Space with the Security Group SpaceGUID
	 * @param securityName
	 * @param spaceGuid
	 * */
	void setSpaceWithSecurityGroup(String securityName, String spaceGuid);
	
	/**
	 * Delete a Particular Security Group
	 * @param securityName
	 * */
	void deleteSecurityGroup(String securityName);
	
	/**
	 * Remove Space from the Security Group
	 * @param securityName
	 * @param spaceName
	 * @param orgName
	 * */
	void deleteSpaceFromSecurityGroup(String securityName, String spaceName, String orgName);
	
	/**
	 * DeleteSpaceFromSecurityGroup
	 * @param securityName
	 * @param spaceGuid
	 * */
	void deleteSpaceFromSecurityGroup(String securityName, String spaceGuid);
	
	/**
	 * Updating a Security Group
	 * @param cloudSecurityGroup
	 * */
	void updateSecurityGroup(CloudSecurityGroup cloudSecurityGroup);
	
	/**
	 * List all Spaces for the Security Group
	 * @param securityName
	 * */
	List<CloudSpace> getSpaceForSecurityGroup(String securityName);
	
	/**
	 * Set a Security Group as a default for staging
	 * @param cloudSecurityGroup
	 * */
	void setSecurityGroupForStaging(CloudSecurityGroup cloudSecurityGroup);
	
	/**
	 * Set a Security Group as a default for running Apps
	 * @param cloudSecurityGroup
	 * */
	void setSecurityGroupForRunningApps(CloudSecurityGroup cloudSecurityGroup);
	
	/**
	 * Removing a Security Group as a default for staging
	 * @param cloudSecurityGroup
	 * */
	void deleteSecurityForStaging(CloudSecurityGroup cloudSecurityGroup);
	
	/**
	 * Removing a Security Group as a default for running Apps
	 * @param cloudSecurityGroup
	 * */
	void deleteSecurityGroupForRunningApps(CloudSecurityGroup cloudSecurityGroup);
	
	/**
	 * Return the Security Groups used for staging
	 * @return List<CloudSecurityGroup>
	 * */
	List<CloudSecurityGroup> getSecurityGroupsForStaging();
	
	/**
	 * Return the Security Groups used for running Apps
	 * @return List<CloudSecurityGroup>
	 * */
	List<CloudSecurityGroup> getSecurityGroupForRunningApps();
	
	/**
	 * List all Events
	 * @return List<CloudEvent>
	 * */
	List<CloudEvent> getAllEvents();
	
	/**
	 * List Event By Fiter
	 * @param eventType
	 * */
	List<CloudEvent> getEventsByEventType(String eventType);
	
	/**
	 * List actee and other events
	 * @param types
	 * */
	List<CloudEvent> getAppEvent(String appGuid);
	
	/**
	 * List events associated with an type enevt since January 1, 2014
	 * sign will contains: <, >, <=, >=, IN
	 * */
	List<CloudEvent> getEventsByActeeAndTimestamp(String actee, String sign, String timestamp);
	
	/**
	 * List all Service Instances Filter CloudSpace 
	 * @param spaceGuid
	 * @return List<CloudService>
	 * */
	List<CloudService> getServicesFromSpace(String spaceGuid);
	
	/**
	 * Terminate the running App Instance at the given index
	 * @param appName 
	 * @param index
	 * */
	void deleteAppInstanceWithIndex(String appName, int index);
	
	/**
	 * Delete a Particular User
	 * @param username
	 * */
	void deleteUserWithUserName(String username);
	
	/**
	 * Downloads the bits for an App
	 * @param appName
	 * @return byte[]
	 * */
	byte[] downloadAppWithAppName(String appName);
	
	/**
	 * List all Buildpacks
	 * @return List<CloudAdminBuildpack>
	 * */
	List<CloudAdminBuildpack> getBuildpacks();
	
   /**
    * Get application environment variables for the app with the specified name.
    *
    * @param appGuid UUID of the app
    * @return the cloud application environment variables
    */
   Map<String, Object> getApplicationEnvironment(UUID appGuid);
   
   /**
	 * Get application environment variables for the app with the specified name.
	 *
	 * @param appName name of the app
	 * @return the cloud application environment variables
	 */
	Map<String, Object> getApplicationEnvironment(String appName);
	
	/**
	 * Get a service instance.
	 *
	 * @param service name of the service instance
	 * @return the service instance info
	 */
	CloudServiceInstance getServiceInstance(String service);
	
	/**
	 * getCloudUserFromOrganizationTeam 
	 * This function is get cloudUser from organization 
	 * @param orgName
	 * @param username
	 * @return CloudUser
	 * */
	CloudUser getCloudUserFromOrganizationTeam(String orgName, String username);
			
	/**
	 * getOrganizationManagers
	 * @param orgName
	 * @return List<CloudUser>
	 * */
	List<CloudUser> getOrganizationManagers(String orgName);
	
	/**
	 * getOrgizationAuditors
	 * @param orgName
	 * @return List<CloudUser>
	 * */
	List<CloudUser> getOrgizationAuditors(String orgName);
	
	/**
	 * getOrgizationBillingManagers
	 * @param orgName
	 * @return List<CloudUser>
	 * */
	List<CloudUser> getOrgizationBillingManagers(String orgName);
	
	/**
	 * getSpaceManagers
	 * @param spaceGuid
	 * @return List<CloudUser>
	 * */
	List<CloudUser> getSpaceManagers(String spaceGuid);
	
	/**
	 * getSpaceAuditors
	 * @param spaceGuid
	 * @return List<CloudUser>
	 * */
	List<CloudUser> getSpaceAuditors(String spaceGuid);
	
	/**
	 * getSpaceDevelopers
	 * @param spaceGuid
	 * @return getSpaceDevelopers
	 * */
	List<CloudUser> getSpaceDevelopers(String spaceGuid);
	
	/**
	 * isOrganizationManager by the organization and user
	 * @param orgName
	 * @param username
	 * @return Boolean 
	 * */
	Boolean isOrganizationManager(String orgName, String username);
	
	/**
	 * isOrganizationBillingManager by the organization and user
	 * @param orgName
	 * @param username
	 * */
	Boolean isOrganizationBillingManager(String orgName, String username);
	
	/**
	 * isOrganizationAuditor by orgName and user
	 * @param orgName
	 * @param username
	 * @return Boolean isOrganizationAuditor
	 * */
	Boolean isOrganizationAuditor(String orgName, String username);
	
	/**
	 * isSpaceManager
	 * @param target organization session space
	 * @param username
	 * @return Boolean isSpaceManager
	 * */
	Boolean isSpaceManager(String spaceGuid, String username);
	
	/**
	 * isSpaceAuditor
	 * @param target organization session space
	 * @param username
	 * @return Boolean isSpaceAuditor
	 * */
	Boolean isSpaceAuditor(String spaceGuid, String username);
	
	/**
	 * isSpaceDeveloper
	 * @param target organization session space
	 * @param username
	 * @return Boolean isSpaceDeveloper
	 * */
	Boolean isSpaceDeveloper(String spaceGuid, String username);
	
	/**
	 * associateManagerOrganization add an user to organization manager role
	 * This function will query all users in CloudFoundry impotent!
	 * function role: admin
	 * @param orgName
	 * @param username
	 * */
	void associateManagerOrganization(String orgName, String username);
	
	/**
	 * associateManagerOrganizationTeam
	 * This function will search one exist organization users' team and associate role 2 the user
	 * function role: organization-manager
	 * @param orgName
	 * @param userGuid
	 * */
	void associateManagerOrganizationTeam(String orgName, String userGuid);
	
	/**
	 * associateBillingManagerOrganization add an user to Billing organization manager role
	 * This function will query all users in CloudFoundry impotent!
	 * function role: admin
	 * @param orgName
	 * @param username
	 * */
	void associateBillingManagerOrganization(String orgName, String username);
	
	/**
	 * associateBillingManagerOrganizationTeam add an user to Billing organization manager role
	 * This function will search one exist organization users' team and associate role 2 the user
	 * function role: organization manager
	 * @param orgName
	 * @param userGuid
	 * */
	void associateBillingManagerOrganizationTeam(String orgName, String userGuid);
	
	/**
	 * associateBillingManagerOrganization add an user to organization manager role
	 * This function will query all users in CloudFoundry impotent!
	 * function role: admin
	 * @param orgName
	 * @param username
	 * */
	void associateAuditorOrganization(String orgName, String username);
	
	/**
	 * associateAuditorOrganizationTeam add an user to organization manager role
	 * This function will search one exist organization users' team and associate role 2 the user
	 * function role: organization manager
	 * @param orgName
	 * @param userGuid
	 * */
	void associateAuditorOrganizationTeam(String orgName, String userGuid);
	
	/**
	 * associateManagerSpace add an user to space manager role
	 * function role: admin
	 * @param CloudSpace
	 * @param username
	 * */
	void associateManagerSpace(CloudSpace cloudSpace, String username);
	
	/**
	 * associateManagerSpaceTeam add an user to space manager role
	 * function role: organization manager
	 * @param CloudSpace
	 * @param userGuid
	 * */
	void associateManagerSpaceTeam(CloudSpace cloudSpace, String userGuid);
	
	/**
	 * associateDeveloperSpace add an user to space manager role
	 * function role: admin 
	 * @param CloudSpace
	 * @param username
	 * */
	void associateDeveloperSpace(CloudSpace cloudSpace, String username);
	
	/**
	 * associateDeveloperSpaceTeam add an user to space manager role
	 * function role: organization manager 
	 * @param CloudSpace
	 * @param userGuid
	 * */
	void associateDeveloperSpaceTeam(CloudSpace cloudSpace, String userGuid);
	
	/**
	 * associateAuditorSpace add an user to space manager role
	 * function role: admin
	 * @param CloudSpace
	 * @param username
	 * */
	void associateAuditorSpace(CloudSpace cloudSpace, String username);
	
	/**
	 * associateAuditorSpaceTeam add an user to space manager role
	 * function role: organization manager
	 * @param CloudSpace
	 * @param userGuid
	 * */
	void associateAuditorSpaceTeam(CloudSpace cloudSpace, String userGuid);
	
	/**
	 * removeOrganizationManager remove user from the organization team
	 * function role: organization manager
	 * @param organization name
	 * @param userGuid
	 * */
	void removeOrganizationManager(String orgName, String userGuid);
	
	/**
	 * removeOrganizationBillingManager remove user from the billingManager team
	 * function role: organization manager
	 * @param orgName
	 * @param userGuid
	 * */
	void removeOrganizationBillingManager(String orgName, String userGuid);
	
	/**
	 * removeOrganizationAuditor remove user from the auditor team
	 * function role: organization manager
	 * @param orgName
	 * @param userGuid
	 * */
	void removeOrganizationAuditor(String orgName, String userGuid);
	
	/**
	 * removeSpaceManager remove user from the space manager team
	 * function role: organization manager
	 * @param space
	 * @param userGuid
	 * */
	void removeSpaceManager(CloudSpace space, String userGuid);
	
	/**
	 * removeSpaceDeveloper remove user from the space developer team
	 * function role: organization manager
	 * @param space
	 * @param userGuid
	 * */
	void removeSpaceDeveloper(CloudSpace space, String userGuid);
	
	/**
	 * removeSpaceAuditor remove user from the space Auditor team
	 * function role: organization manager
	 * @param space
	 * @param userGuid
	 * */
	void removeSpaceAuditor(CloudSpace space, String userGuid);
	
	/**
	 * addSharedDomain add shared domain not the private domain.
	 * This function is dangerous.
	 * @param sharedDomainName
	 * */
	void addSharedDomain(String sharedDomainName);
	
	/**
	 * removeShareDomain remove sharedDomain not the private domain.
	 * This function is dangerous. 
	 * @param sharedDomainName
	 * */
	void removeShareDomain(String sharedDomainName);
	
	/**
	 * updateOrganization update organization
	 * function role : admin
	 * */
	void updateOrganization(CloudOrganization organization);
	
	/**
	 * getOrganizationNameWithGuid get organization name
	 * function role : all
	 * @param orgGuid
	 * @return String
	 * */
	String getOrganizationNameWithGuid(String orgGuid);
	
	/**
	 * getSpaceNameWithGuid get space name
	 * function role : all
	 * @param orgGuid
	 * @return String
	 * */
	String getSpaceNameWithGuid(String spaceGuid);
	
	/**
	 * getOrganizationMemoryUsage Unit:MB
	 * funciton role : all
	 * @param orgName
	 * @return long mem usage
	 * */
	Integer getOrganizationMemoryUsage(String organizationName);
	
	/**
	 * getOrganizationUserGuid 
	 * function role : all
	 * @param orgName
	 * @param username
	 * @return UUID
	 * */
	UUID getOrganizationUserGuid(String orgName, String username);
	
	/**
	 * The function is support by 207 version
	 * @param orgName
	 * @param username
	 * */
	List<String> getUserRolesWithOrganization(String orgName, String username);
	
	/**
	 * This function is get accessCodeToken
	 * @param credentials
	 * @return OAuth2AccessToken
	 * */
	OAuth2AccessToken getAccessCodeToken(CloudCredentials credentials);
	
	/**
	 * This function is find AD user by username
	 * ROLE admin
	 * @param username
	 * @param isAdmin 
	 * @return CloudUser
	 * */
	CloudUser findADUserByUsername(String username,Boolean isAdmin);
	
	/**
	 * This function is get all AD users
	 * ROLE admin 
	 * @return list cloudusers
	 * */
	List<CloudUser> getADAllUsers();
	
	/**
	 * getCurrentUserId
	 * 获取当前用户下的用户ID
	 * @return String 
	 * */
	String getCurrentUserId();
	
	List<CloudOrganization> getCurrentUserOrganizations();
	
	List<Map<String,Object>> getUaaUsersWithType(String type);
	
	void resetUserPassword(String username);
	
	List<Map<String,Object>> getAllResourcesWithparams(String urlPath, Map<String,Object> params);
	
	Map<String,Object> getResourceWithparams(String urlPath, Map<String,Object> params);
	
	String getOneObjectWithGuid(String urlPath);
	
	/**
	 * getCloudEntity
	 * @param requestType
	 * @param name
	 * @param depth
	 * @return Map<String, Object>
	 * "quota_definitions", "default", "0"  --> "/v2/quota_definitions?inline-relations-depth=0&q=name:default"
	 * supprot spaces,apps,orgs,services,service_instances... not support service_plans,users
	 * */
	Map<String, Object> getCloudEntity(String requestType, String name, String depth);
	
	/**
	 * getCloudResourcesWithPrefix
	 * Map<String,String> prefixMap = new HashMap<String, String>();
	 * prefixMap.put("spaces", "mycloud");
	 * client.getCloudResourcesWithPrefix(prefixMap, "apps", "1");
	 * "/v2/spaces/{space}/apps?inline-relations-depth=1"
	 * support spaces,orgs,apps,quotas,service_instances,service_plans,services . not support users
	 * */
	List<Map<String,Object>> getCloudResourcesWithPrefix(Map<String,String> prefix, String requestType, String depth);
	
	/**
	 * getCloudEntityWithPrefix
	 * prefixMap.put("spaces", "developer");
	 * client.getCloudEntityWithPrefix(prefixMap, "services", "jojopost", "1");
	 * "/v2/spaces/{space}/services?inline-relations-depth=1&q=label:elephantsql"
	 * support spaces,apps,orgs,services,service_instances,quotas... not support service_plans,users
	 * */
	Map<String, Object> getCloudEntityWithPrefix(Map<String,String> prefix, String requestType, String name, String depth);
	
	/**
	 * getCloudResources
	 * "/v2/apps?inline-relations-depth=1"
	 * */
	List<Map<String,Object>> getCloudResources(String requestType, String depth);
	
	/**
	 * getObjectGuid
	 * "/v2/apps" get the requestType's guid
	 * support apps,spaces,orgs,services,services,service_instances,quotas... not support users,service_plans.
	 * */
	String getObjectGuid(String requestType, String name);
	
}

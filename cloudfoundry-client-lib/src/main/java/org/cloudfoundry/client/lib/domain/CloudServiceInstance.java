package org.cloudfoundry.client.lib.domain;

import java.util.List;
import java.util.Map;

/**
 * Class representing a service instance.
 *
 * @author Scott Frederick
 */
public class CloudServiceInstance extends CloudEntity {

	private CloudService service;
	private CloudServicePlan servicePlan;

	private String type;
	private String dashboardUrl;
	private Map<String, Object> credentials;
	private List<CloudServiceBinding> bindings;

	public CloudServiceInstance() {
		super();
	}

	public CloudServiceInstance(Meta meta, String name) {
		super(meta, name);
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getDashboardUrl() {
		return dashboardUrl;
	}

	public void setDashboardUrl(String dashboardUrl) {
		this.dashboardUrl = dashboardUrl;
	}

	public Map<String, Object> getCredentials() {
		return credentials;
	}

	public void setCredentials(Map<String, Object> credentials) {
		this.credentials = credentials;
	}

	public List<CloudServiceBinding> getBindings() {
		return bindings;
	}

	public void setBindings(List<CloudServiceBinding> bindings) {
		this.bindings = bindings;
	}

	public CloudService getService() {
		return service;
	}

	public void setService(CloudService service) {
		this.service = service;
	}

	public CloudServicePlan getServicePlan() {
		return servicePlan;
	}

	public void setServicePlan(CloudServicePlan servicePlan) {
		this.servicePlan = servicePlan;
	}
}
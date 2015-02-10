package org.cloudfoundry.client.lib.domain;

import java.util.List;

public class CloudSecurityGroup extends CloudEntity{
	
	private List<CloudSecurityRules> rules;
	
	private Boolean running_default;
	
	private Boolean staging_default;
	
	private List<CloudSpace> cloudSpaces;

	public CloudSecurityGroup(Meta meta, String name,List<CloudSecurityRules> rules,
			Boolean running_default, Boolean staging_default,
			List<CloudSpace> cloudSpaces) {
		super(meta, name);
		this.rules = rules;
		this.running_default = running_default;
		this.staging_default = staging_default;
		this.cloudSpaces = cloudSpaces;
	}
	
	public CloudSecurityGroup(Meta meta, String name) {
		super(meta, name);
	}

	public CloudSecurityGroup(Meta meta, String name,List<CloudSecurityRules> rules) {
		super(meta, name);
		this.rules = rules;
	}

	public CloudSecurityGroup(List<CloudSpace> cloudSpaces, String name, Meta meta) {
		super(meta, name);
		this.cloudSpaces = cloudSpaces;
	}

	public List<CloudSecurityRules> getRules() {
		return rules;
	}

	public void setRules(List<CloudSecurityRules> rules) {
		this.rules = rules;
	}

	public Boolean getRunning_default() {
		return running_default;
	}

	public void setRunning_default(Boolean running_default) {
		this.running_default = running_default;
	}

	public Boolean getStaging_default() {
		return staging_default;
	}

	public void setStaging_default(Boolean staging_default) {
		this.staging_default = staging_default;
	}

	public List<CloudSpace> getCloudSpaces() {
		return cloudSpaces;
	}

	public void setCloudSpaces(List<CloudSpace> cloudSpaces) {
		this.cloudSpaces = cloudSpaces;
	}
}

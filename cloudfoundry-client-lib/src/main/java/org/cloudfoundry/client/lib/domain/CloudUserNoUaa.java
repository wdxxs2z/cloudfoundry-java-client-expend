package org.cloudfoundry.client.lib.domain;

import java.util.List;

public class CloudUserNoUaa extends CloudEntity{
	
	private List<CloudOrganization> organizations;
	
	private List<CloudOrganization> managed_organizations;
	
	private List<CloudOrganization> audited_organizations;
	
	private List<CloudSpace> spaces;
	
	private List<CloudSpace> managed_spaces;
	
	private List<CloudSpace> audited_spaces;
	
	private Boolean active;
	
	private Boolean admin;
	
	public CloudUserNoUaa(Meta meta, String name){
		super(meta, name);
	}
	
	public CloudUserNoUaa(Meta meta, String name,List<CloudOrganization> organizations,List<CloudSpace> spaces) {
		super(meta, name);
		this.organizations = organizations;
		this.spaces = spaces;
	}
	
	public CloudUserNoUaa(Meta meta, String name, Boolean admin, Boolean active,List<CloudOrganization> organizations, List<CloudOrganization> managed_organizations,
			List<CloudOrganization> audited_organizations, List<CloudSpace> spaces, List<CloudSpace> managed_spaces,
			List<CloudSpace> audited_spaces) {
		super(meta, name);
		this.admin = admin;
		this.active = active;
		this.organizations = organizations;
		this.managed_organizations = managed_organizations;
		this.audited_organizations = audited_organizations;
		this.spaces = spaces;
		this.managed_spaces = managed_spaces;
		this.audited_spaces = audited_spaces;
	}
	
	public List<CloudOrganization> getOrganizations() {
		return organizations;
	}

	public void setOrganizations(List<CloudOrganization> organizations) {
		this.organizations = organizations;
	}

	public List<CloudOrganization> getManaged_organizations() {
		return managed_organizations;
	}

	public void setManaged_organizations(
			List<CloudOrganization> managed_organizations) {
		this.managed_organizations = managed_organizations;
	}

	public List<CloudOrganization> getAudited_organizations() {
		return audited_organizations;
	}

	public void setAudited_organizations(
			List<CloudOrganization> audited_organizations) {
		this.audited_organizations = audited_organizations;
	}

	public List<CloudSpace> getSpaces() {
		return spaces;
	}

	public void setSpaces(List<CloudSpace> spaces) {
		this.spaces = spaces;
	}

	public List<CloudSpace> getManaged_spaces() {
		return managed_spaces;
	}

	public void setManaged_spaces(List<CloudSpace> managed_spaces) {
		this.managed_spaces = managed_spaces;
	}

	public List<CloudSpace> getAudited_spaces() {
		return audited_spaces;
	}

	public void setAudited_spaces(List<CloudSpace> audited_spaces) {
		this.audited_spaces = audited_spaces;
	}

	public Boolean getActive() {
		return active;
	}

	public void setActive(Boolean active) {
		this.active = active;
	}

	public Boolean getAdmin() {
		return admin;
	}

	public void setAdmin(Boolean admin) {
		this.admin = admin;
	}
}

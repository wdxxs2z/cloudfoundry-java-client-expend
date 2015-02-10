package org.cloudfoundry.client.lib.domain;

public class CloudEvent extends CloudEntity{
	
	private String type;
	
	private String actor;
	
	private String actor_type;
	
	private String actor_name;
	
	private String actee;
	
	private String actee_type;
	
	private String actee_name;
	
	private String timestamp;
	
	private String space_guid;
	
	private String organization_guid;
	
	private String description;

	public CloudEvent(Meta meta, String name,String type, 
			String actor, String actor_type,
			String actor_name, String actee, String actee_type,
			String actee_name, String timestamp, String space_guid,
			String organization_guid, String description) {
		super(meta, name);
		this.type = type;
		this.actor = actor;
		this.actor_type = actor_type;
		this.actor_name = actor_name;
		this.actee = actee;
		this.actee_type = actee_type;
		this.actee_name = actee_name;
		this.timestamp = timestamp;
		this.space_guid = space_guid;
		this.organization_guid = organization_guid;
		this.description = description;
	}

	public CloudEvent(Meta meta, String name,String type, 
			String actor_type, String actor_name,
			String actee_type, String actee_name, String timestamp,
			String description) {
		super(meta, name);
		this.type = type;
		this.actor_type = actor_type;
		this.actor_name = actor_name;
		this.actee_type = actee_type;
		this.actee_name = actee_name;
		this.timestamp = timestamp;
		this.description = description;
	}
	
	public CloudEvent(Meta meta, String name,String type, 
			String actor_type, String actor_name,
			String actee_type, String actee_name, String timestamp,
			String space_guid, String organization_guid, String description) {
		super(meta, name);
		this.type = type;
		this.actor_type = actor_type;
		this.actor_name = actor_name;
		this.actee_type = actee_type;
		this.actee_name = actee_name;
		this.timestamp = timestamp;
		this.space_guid = space_guid;
		this.organization_guid = organization_guid;
		this.description = description;
	}

	public String getDescription() {
		return description;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public String getType() {
		return type;
	}

	public void setType(String type) {
		this.type = type;
	}

	public String getActor() {
		return actor;
	}

	public void setActor(String actor) {
		this.actor = actor;
	}

	public String getActor_type() {
		return actor_type;
	}

	public void setActor_type(String actor_type) {
		this.actor_type = actor_type;
	}

	public String getActor_name() {
		return actor_name;
	}

	public void setActor_name(String actor_name) {
		this.actor_name = actor_name;
	}

	public String getActee() {
		return actee;
	}

	public void setActee(String actee) {
		this.actee = actee;
	}

	public String getActee_type() {
		return actee_type;
	}

	public void setActee_type(String actee_type) {
		this.actee_type = actee_type;
	}

	public String getActee_name() {
		return actee_name;
	}

	public void setActee_name(String actee_name) {
		this.actee_name = actee_name;
	}

	public String getTimestamp() {
		return timestamp;
	}

	public void setTimestamp(String timestamp) {
		this.timestamp = timestamp;
	}

	public String getSpace_guid() {
		return space_guid;
	}

	public void setSpace_guid(String space_guid) {
		this.space_guid = space_guid;
	}

	public String getOrganization_guid() {
		return organization_guid;
	}

	public void setOrganization_guid(String organization_guid) {
		this.organization_guid = organization_guid;
	}
}

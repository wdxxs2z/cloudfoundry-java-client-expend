package org.cloudfoundry.client.lib.domain;


public class CloudAdminBuildpack extends CloudEntity{
	
	private String filename;
	private int position;
	private Boolean enabled;
	private Boolean locked;
	
	public CloudAdminBuildpack(Meta meta, String name, String filename, int position,
			Boolean enabled, Boolean locked) {
		super(meta, name);
		this.filename = filename;
		this.position = position;
		this.enabled = enabled;
		this.locked = locked;
	}
	public String getFilename() {
		return filename;
	}
	public void setFilename(String filename) {
		this.filename = filename;
	}
	public int getPosition() {
		return position;
	}
	public void setPosition(int position) {
		this.position = position;
	}
	public Boolean getEnabled() {
		return enabled;
	}
	public void setEnabled(Boolean enabled) {
		this.enabled = enabled;
	}
	public Boolean getLocked() {
		return locked;
	}
	public void setLocked(Boolean locked) {
		this.locked = locked;
	}
}
